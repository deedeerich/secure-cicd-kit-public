#!/usr/bin/env python3
"""Under the seam, an application rollback never reverses what the landing zone owns, and never takes
the landing zone's evidence for its own. (OF-5 K-5; KDEC-030 "Rollback: what the generic ARM rollback
must refuse"; the contract's negative test prove_seam_app_rollback_refuses_shared_entry)

WHY THIS EXISTS

    The kit's generic ARM rollback (reusable-rollback-sequence.yml, `adapter: arm`) reverses
    SHARED_MULTI_CONFIG entries -- Front Door routes, NSG rules, WAF rules, DNS records -- from any
    deployer's resources.json. The landing zone creates exactly those entries for each workload and is
    their only reverser (its own recovery, entry level, tested after every step; R4). Two systems
    reversing one entry is the hazard. So rollback-resource-classes.yaml now names each type's
    `entry_owner`, and with the seam in force (the reusable passes --seam-ownership when the
    environment opts into the KDEC-030 lease):

      * a node whose type the landing zone owns is never read for reversal and never written:
        ROLLBACK_REFUSED_PLATFORM_OWNED (routed ROLLBACK_REQUIRES_HUMAN_DECISION, the landing zone's
        recovery named as the reverser); a release target (sites, containerApps) is refused the
        same way for a whole-body ARM PUT -- its kit fields are the deploy adapters' to reverse;
      * everything tied to a refused node is held as for a cross-edit; a free node is reversed only
        when nothing ties it to a refused one;
      * a step whose resources.json is not a kit deploy's of the locked target (a landing-zone apply's
        evidence, or another target's) is refused before anything is read live:
        ROLLBACK_REFUSED_FOREIGN_EVIDENCE.

    Off (no seam): the SHARED/STABLE mechanics are unchanged (tests/prove_rollback_dependencies.py),
    because a deployer that is not a landing zone still owns its own entries.

CASES
    E1  the registry: every type has an entry_owner; every SHARED type, and the platform STABLE types,
        are landing-zone; sites and containerApps are kit-release-fields
    E2  seam on: a Front Door route, a DNS record and a WAF rule, plus one release-owned container group
        independent of them -> the three refused ROLLBACK_REFUSED_PLATFORM_OWNED, never GET-for-reversal
        and never PUT/DELETE; the container group reversed; outcome ROLLBACK_REFUSED_PLATFORM_OWNED,
        ROLLBACK_REQUIRES_HUMAN_DECISION, the step stopped for a human
    E3  seam on: the free node depends on a refused one -> nothing reversed at all
    E4  seam on: a landing-zone apply's evidence (release_id lz-apply:...) -> ROLLBACK_REFUSED_FOREIGN_EVIDENCE,
        zero az calls; evidence naming another target -> the same
    E5  seam off: the same shared release reverses as before (control)
    W1  the rollback reusable passes --seam-ownership exactly when KIT_TARGET_LEASE_ACCOUNT is set

EXIT 0 proven   1 a case failed   2 could not be checked
"""
import copy
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
import prove_rollback_dependencies as P  # noqa: E402  (the shared stub estate and its runner)
import _workflow_runner as W  # noqa: E402

ENGINE = os.path.join(ROOT, 'scripts', 'rollback_sequence.py')
FAILS = []
DNS = P.RG + '/Microsoft.Network/dnsZones/shop.example'
WAF = P.RG + '/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/wafshared'
ACI = P.RG + '/Microsoft.ContainerInstance/containerGroups/shop-worker'


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def estate():
    arm = P.base_shared()
    arm[DNS] = {'id': DNS, 'name': 'shop.example', 'type': 'Microsoft.Network/dnsZones', 'properties': {}}
    arm[WAF] = {'id': WAF, 'name': 'wafshared', 'type': 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies',
                'properties': {'customRules': {'rules': []}}}
    return arm


def release(depends=False):
    """Release 601: a Front Door route, a DNS record and a WAF rule (all landing-zone entries) and a
    container group the release created in its own resource group."""
    arm = estate()
    before = copy.deepcopy(arm)
    route = {'id': P.AFD + '/afdEndpoints/ep-shared/routes/shop-route', 'name': 'shop-route',
             'properties': {'patternsToMatch': ['/shop/*'],
                            'originGroup': {'id': P.AFD + '/originGroups/billing-og'}}}
    rec = {'id': DNS + '/CNAME/www', 'name': 'www', 'properties': {'CNAMERecord': {'cname': 'ep.azurefd.example'}}}
    waf_rule = {'id': WAF + '/customRules/shopblock', 'name': 'shopblock', 'properties': {'priority': 10}}
    aci = {'id': ACI, 'name': 'shop-worker', 'type': 'Microsoft.ContainerInstance/containerGroups',
           'tags': {'release_ownership_stamp': P.stamp('601')}, 'properties': {'osType': 'Linux'}}
    if depends:
        aci['properties']['dnsNameLabel'] = 'see ' + rec['id']
    nodes = [{'id': route['id'], 'action': 'CREATED', 'prior': None, 'post': route},
             {'id': rec['id'], 'action': 'CREATED', 'prior': None, 'post': rec},
             {'id': waf_rule['id'], 'action': 'CREATED', 'prior': None, 'post': waf_rule},
             {'id': aci['id'], 'action': 'CREATED', 'prior': None, 'post': aci}]
    for n in nodes:
        arm[n['id']] = copy.deepcopy(n['post'])
    return before, arm, nodes


def run_seq(world, runs, seam, evidence_patch=None):
    if evidence_patch:
        evidence_patch(world)
    io.open(world.log, 'w').close()
    seq = os.path.join(world.dir, 'sequence.json')
    io.open(seq, 'w', encoding='utf-8').write(json.dumps({'sequence_id': 'seam', 'steps': [
        {'deployment': 'run %s' % r, 'run_id': r, 'run_attempt': '1', 'adapter': 'arm'} for r in runs]}))
    fx = os.path.join(world.dir, 'e2e.py')
    io.open(fx, 'w', encoding='utf-8').write(P.E2E)
    e2e_log = os.path.join(world.dir, 'e2e.log')
    io.open(e2e_log, 'w').close()
    out = os.path.join(world.dir, 'record.json')
    if os.path.exists(out):
        os.remove(out)
    env = dict(os.environ)
    env.update({'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1', 'fake_az_state': world.state,
                'fake_az_log': world.log, 'e2e_log': e2e_log, 'PATH': world.bin + os.pathsep + env.get('PATH', ''),
                'health_retries'.upper(): '1', 'health_interval_seconds'.upper(): '0'})
    for k in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
        env.pop(k, None)
    kv = os.path.join(world.dir, 'kv.txt')
    io.open(kv, 'w').close()
    args = [sys.executable, ENGINE, 'run', '--sequence', seq, '--evidence-root', world.evidence, '--work',
            os.path.join(world.dir, 'work-%d' % len(os.listdir(world.dir))), '--out', out, '--e2e-command',
            '"%s" "%s"' % (sys.executable, fx), '--test-period-seconds', '1', '--locked-target', 'rg-a/shop',
            '--github-output', kv] + (['--seam-ownership'] if seam else [])
    p = subprocess.run(args, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace')
    try:
        record = json.load(io.open(out, encoding='utf-8'))
    except (OSError, ValueError):
        record = {'result': None, 'why': (p.stdout + p.stderr)[-1500:], 'steps': []}
    outputs = dict(l.rstrip('\n').split('=', 1) for l in io.open(kv, encoding='utf-8') if '=' in l)
    return record, outputs, world.calls(), p.stdout + p.stderr


def reads(calls, rid):
    return [c for c in calls if c[:2] == ['az', 'rest'] and rid.lower() in ' '.join(c).lower()]


def registry():
    import rollback_dependencies as rd
    reg = rd.load_registry()
    platform_stable = ('Microsoft.Web/serverfarms', 'Microsoft.App/managedEnvironments',
                       'Microsoft.Network/privateEndpoints', 'Microsoft.ManagedIdentity/userAssignedIdentities',
                       'Microsoft.Authorization/roleAssignments', 'Microsoft.KeyVault/vaults',
                       'Microsoft.Storage/storageAccounts', 'Microsoft.ContainerRegistry/registries',
                       'Microsoft.Sql/servers', 'Microsoft.Sql/servers/databases')
    owners = dict((k, v.get('entry_owner')) for k, v in reg['types'].items())
    expect(all(o in ('landing-zone', 'kit-release-fields', 'release') for o in owners.values()),
           'E1 every registered type names its entry_owner (%s)' % sorted(k for k, o in owners.items() if not o))
    expect(all(owners[k] == 'landing-zone' for k, v in reg['types'].items() if v['class'] == 'SHARED_MULTI_CONFIG'),
           'E1 every SHARED_MULTI_CONFIG type is landing-zone owned at entry level')
    expect(all(owners.get(t) == 'landing-zone' for t in platform_stable), 'E1 the platform STABLE types are landing-zone')
    expect(owners.get('Microsoft.Web/sites') == 'kit-release-fields' and
           owners.get('Microsoft.App/containerApps') == 'kit-release-fields',
           'E1 sites and containerApps are kit-release-fields (the deploy adapters reverse the kit\'s own fields)')


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    registry()
    # E2: refused entries, one free node reversed
    before, arm, nodes = release()
    world = P.World(arm, [('601', nodes)])
    try:
        record, outputs, calls, log = run_seq(world, ['601'], seam=True)
        rv = P.review(record)
        names = dict((n['id'], n) for n in rv.get('nodes') or [])
        refused = [nid for nid in (nodes[0]['id'], nodes[1]['id'], nodes[2]['id'])
                   if (names.get(nid) or {}).get('decision') == 'left' and
                   'ROLLBACK_REFUSED_PLATFORM_OWNED' in (names.get(nid) or {}).get('reason', '')]
        expect(rv.get('outcome') == 'ROLLBACK_REFUSED_PLATFORM_OWNED' and len(refused) == 3,
               'E2 the route, the DNS record and the WAF rule are ROLLBACK_REFUSED_PLATFORM_OWNED (%s, %d refused)'
               % (rv.get('outcome'), len(refused)))
        expect(rv.get('rollback_state') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and
               "landing zone's recovery" in json.dumps(rv.get('not_reversed')),
               'E2 a human decides, and the landing zone\'s recovery is named as the reverser')
        touched = [c for n in nodes[:3] for c in reads(calls, n['id'])]
        expect(not touched, 'E2 nothing of the three is read for reversal or written (%d az call(s))' % len(touched))
        expect(world.read()['arm'].get(ACI) is None and any(r['id'] == ACI for r in rv.get('reversed') or []),
               'E2 the independent container group the release created is reversed (deleted)')
        expect(all(world.read()['arm'].get(n['id']) is not None for n in nodes[:3]),
               'E2 every landing-zone entry is still there')
        expect(record.get('result') != 'ROLLBACK_SEQUENCE_VERIFIED' and
               outputs.get('rollback_state') == 'ROLLBACK_REQUIRES_HUMAN_DECISION',
               'E2 the sequence does not claim a verified rollback (%s)' % record.get('result'))
    finally:
        world.close()
    # E3: the free node depends on a refused one
    before, arm, nodes = release(depends=True)
    world = P.World(arm, [('601', nodes)])
    try:
        record, outputs, calls, log = run_seq(world, ['601'], seam=True)
        rv = P.review(record)
        expect(rv.get('outcome') == 'ROLLBACK_REFUSED_PLATFORM_OWNED' and not (rv.get('reversed') or []) and
               not P.writes(calls) and world.read()['arm'].get(ACI) is not None,
               'E3 a node tied to a refused one is held too: nothing reversed (%s, %d write(s))'
               % (rv.get('outcome'), len(P.writes(calls))))
    finally:
        world.close()
    # E4: foreign evidence
    before, arm, nodes = release()
    world = P.World(arm, [('601', nodes)])
    try:
        def lz(w):
            p = os.path.join(w.evidence, 'deploy-evidence-601-1', 'resources.json')
            d = json.load(io.open(p, encoding='utf-8'))
            d['release_id'] = 'lz-apply:org/platform/11-1'
            io.open(p, 'w', encoding='utf-8').write(json.dumps(d))
        record, outputs, calls, log = run_seq(world, ['601'], seam=True, evidence_patch=lz)
        expect('ROLLBACK_REFUSED_FOREIGN_EVIDENCE' in (record.get('why') or '') and not calls and
               outputs.get('rollback_refusal') == 'ROLLBACK_REFUSED_FOREIGN_EVIDENCE',
               'E4 a landing-zone apply\'s evidence is ROLLBACK_REFUSED_FOREIGN_EVIDENCE before anything is read '
               '(%d az call(s); %s)' % (len(calls), (record.get('why') or '')[:160]))

        def other(w):
            p = os.path.join(w.evidence, 'deploy-evidence-601-1', 'resources.json')
            d = json.load(io.open(p, encoding='utf-8'))
            d['release_id'] = 'run-601-1'
            d['target'] = {'resource_group': 'rg-a', 'name': 'someone-else'}
            io.open(p, 'w', encoding='utf-8').write(json.dumps(d))
        record, outputs, calls, log = run_seq(world, ['601'], seam=True, evidence_patch=other)
        expect('ROLLBACK_REFUSED_FOREIGN_EVIDENCE' in (record.get('why') or '') and not calls,
               'E4 evidence of another target than the locked one is refused the same way')
    finally:
        world.close()
    # E5: control -- the seam off, the shared release reverses as KDEC-023 built it
    before, arm, nodes = P.shared_release()
    world = P.World(arm, [('501', nodes)])
    try:
        record, outputs, calls, log = run_seq(world, ['501'], seam=False)
        rv = P.review(record)
        expect(rv.get('outcome') == 'ROLLBACK_SCOPED_TO_PRODUCT_CONFIG' and
               record.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED',
               'E5 control: without the seam, the product\'s shared entries still roll back (%s, %s)'
               % (rv.get('outcome'), record.get('result')))
    finally:
        world.close()
    # W1
    import _step_harness as H
    s = H.step('.github/workflows/reusable-rollback-sequence.yml', 'rollback', 'sequence') or {}
    body = s.get('run') or ''
    expect('--seam-ownership' in body and 'KIT_TARGET_LEASE_ACCOUNT' in body,
           'W1 the rollback reusable passes --seam-ownership when the environment opts into the lease')
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: under the seam the ARM rollback never reads for reversal or writes a landing-zone entry '
          '(ROLLBACK_REFUSED_PLATFORM_OWNED), holds whatever is tied to one, reverses only independent '
          'release-owned nodes, and refuses evidence that is not a kit deploy of the locked target '
          '(ROLLBACK_REFUSED_FOREIGN_EVIDENCE); without the seam, nothing changes.')
    print('      STUBBED: the ARM estate is tests/_fake_az.py; the live seam is the integrated gate (KDEC-030 O-7).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
