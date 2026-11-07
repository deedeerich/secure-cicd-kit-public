#!/usr/bin/env python3
"""Cross-edited rollback: shared multi-config resources roll back only the product's entries; a
stable resource changed by someone else gets a dependency review, a partial or no rollback, and a
graph; a deploy after a rollback is checked for dependencies on what was rolled back.
(KDEC-023, owner 2026-10-23; lane L-RB3; scripts/rollback_dependencies.py, scripts/rollback_hold.py,
rollback-resource-classes.yaml.)

WHY THIS EXISTS

    Owner, 2026-10-23: "if someone else or a different service edited something then we need to
    follow the same cross edited rollback rules. If it's a resource or service that is not shared
    and multi-configurable for each thing think frontdoor or NSGs or firewall rules and routing or
    WAF rules and routing that are shared but only the product's configs were changed those things
    can be rolled back but if a solid stable resource like an app service or a database or a
    container or something is changed by something else the dependency review and refusal to
    rollback fully and the partial or no rollback with reasons and dependency graph is provided to
    the user."

    And, on a deploy that arrives while a rollback runs: "That's a conflict where the rollback must
    finish and then the other one can deploy...problem is if someone is trying to deploy they are
    probably trying to use the infrastructure and code from the one we just rolled back...that
    needs discussion and planning." The HOLD below is the safe default; the options are KDEC-023.

HOW

    One stateful stub cloud (tests/_fake_az.py, which now models ARM through `az rest`) holds a
    shared NSG, a shared Front Door profile, a shared Application Gateway and the product's stable
    resources. A deployer's evidence (`resources.json`: every node the release created or modified,
    with the body before and after) is written as the deploy left it; the sequence is then run by
    scripts/rollback_sequence.py as the reusable runs it (`adapter: arm`). The hold is proven by
    scripts/rollback_hold.py against a recorded GitHub API, and by running both deploy reusables AS
    SHIPPED (tests/_workflow_runner.py) against it.

WHAT IT PROVES

    D1  SHARED, ONLY OTHER PRODUCTS MOVED: a release created an NSG rule, changed another, created
        a Front Door route and origin group and an Application Gateway listener; since then another
        product changed ITS OWN NSG rule. Rolled back: only the product's entries, every other
        entry and each parent read back BYTE-IDENTICAL before and after, no PUT or DELETE on
        anything but the product's entries -> ROLLBACK_SCOPED_TO_PRODUCT_CONFIG,
        ELIGIBLE_OWNED_PART_SEPARABLE, ROLLBACK_SEQUENCE_VERIFIED
    D2  ANOTHER ACTOR CHANGED ONE OF THE PRODUCT'S OWN NSG RULES: the cross-edit rules apply. That
        rule, and the product's other rule in the same NSG (NSG rules interact by priority), are
        left; the Front Door and gateway entries, independent, are reversed ->
        ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT, ROLLBACK_STEP_PARTIAL, the sequence stopped for a
        human, ROLLBACK_REQUIRES_HUMAN_DECISION
    D3  AN APP SERVICE CHANGED BY ANOTHER ACTOR: a FULL rollback is refused; the storage account
        and the NSG rule (independent) are reversed; the App Service and the Key Vault it
        references are left, each with its reason; the dependency graph (nodes marked unchanged /
        changed by this release / changed by other, edges app -> vault) is in the record, as JSON
        and Mermaid in the step's evidence directory, and in the run summary
    D4  A DATABASE CHANGED BY ANOTHER ACTOR: everything the release changed depends on it, so
        NOTHING is rolled back (zero PUT/DELETE) -> ROLLBACK_REFUSED_DEPENDENCY_CONFLICT, the step
        ineligible with ROLLBACK_REQUIRES_HUMAN_DECISION, the graph emitted
    D5  THE RECORD validates against schemas/rollback-sequence.schema.json (version 3), and names
        the rollback_state; every Azure type in the registry has one of the two classes
    KDEC-023 item 4 (owner, 2026-10-23): "We need to do a dependency check on the incoming
    deployment to ensure that it isn't reliant on things that were just rolled back ... If there are
    no dependencies on rolled back items then deploy it."
    D6  THE ROLLBACK WRITES A MARKER for its target: its run, the releases it rolled back (with their
        commits and images), and every node it changed with the state it left (gone, or restored)
    D7  THE CHECK ON AN INCOMING DEPLOY whose base predates the rollback: built on the rolled-back
        commit, declaring a dependency on an entry the rollback removed or changed, or bringing back
        a rolled-back image -> DEPLOY_REFUSED_ROLLBACK_DEPENDENCY, with a report naming the rollback
        and each dependency (old -> new, or no longer exists); not dependent ->
        DEPLOY_NO_ROLLBACK_DEPENDENCY, proceeds with the note; based after the rollback ->
        ROLLBACK_CHECK_NOT_REQUIRED; state unreadable -> ROLLBACK_DEPENDENCY_CHECK_INCOMPLETE,
        refused, never blind. There is no override input: the fix is to correct the deploy.
    D8  BOTH DEPLOY REUSABLES, AS SHIPPED: dependent -> refused at the check BEFORE login (zero az
        calls), routing BLOCKED, the report in the summary and the evidence; not dependent -> the
        deploy runs and keeps the check's note; the rollback reusable writes the marker

    STUBBED, NOT LIVE. Whether ARM accepts each PUT of a prior body, whether the artifact and
    commit APIs answer as recorded, are a live run.

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import copy
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

ENGINE = os.path.join(ROOT, 'scripts', 'rollback_sequence.py')
HOLD = os.path.join(ROOT, 'scripts', 'rollback_hold.py')
RG = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-a/providers'
NSG = RG + '/Microsoft.Network/networkSecurityGroups/nsg-shared'
AFD = RG + '/Microsoft.Cdn/profiles/afd-shared'
AGW = RG + '/Microsoft.Network/applicationGateways/agw-shared'
APP = RG + '/Microsoft.Web/sites/app-shop'
KV = RG + '/Microsoft.KeyVault/vaults/kv-shop'
ST = RG + '/Microsoft.Storage/storageAccounts/stshopstatic'
DB = RG + '/Microsoft.Sql/servers/sql-shop/databases/shopdb'
HOST = 'shop.example'
E2E = '''import io, json, os, sys
s = json.load(io.open(os.environ['fake_az_state'], encoding='utf-8'))
io.open(os.environ['e2e_log'], 'a', encoding='utf-8').write(os.environ.get('rollback_step'.upper(), '') + '\\n')
sys.exit(1 if s.get('e2e_fails') else 0)
'''


def stamp(run):
    return 'release_id=run-%s-1' % run


def rule(name, prio, port, desc='', src='10.0.0.0/24'):
    return {'id': NSG + '/securityRules/' + name, 'name': name,
            'type': 'Microsoft.Network/networkSecurityGroups/securityRules',
            'properties': {'priority': prio, 'direction': 'Inbound', 'access': 'Allow',
                           'protocol': 'Tcp', 'destinationPortRange': str(port),
                           'sourceAddressPrefix': src, 'description': desc}}


def base_shared():
    """The shared estate before the product's release: other products' entries already there."""
    arm = {}
    arm[NSG] = {'id': NSG, 'name': 'nsg-shared', 'type': 'Microsoft.Network/networkSecurityGroups',
                'location': 'eastus', 'tags': {'owner': 'platform'}, 'properties': {}}
    for r in (rule('billing-allow-8443', 200, 8443, 'product=billing'),
              rule('shop-deny-legacy', 310, 8080, stamp('400'))):
        arm[r['id']] = r
    arm[AFD] = {'id': AFD, 'name': 'afd-shared', 'type': 'Microsoft.Cdn/profiles',
                'sku': {'name': 'Standard_AzureFrontDoor'}, 'properties': {}}
    arm[AFD + '/afdEndpoints/ep-shared'] = {'id': AFD + '/afdEndpoints/ep-shared', 'name': 'ep-shared',
                                           'properties': {'hostName': 'ep-shared.azurefd.example'}}
    arm[AFD + '/originGroups/billing-og'] = {'id': AFD + '/originGroups/billing-og', 'name': 'billing-og',
                                            'properties': {'healthProbeSettings': {'probePath': '/h'}}}
    arm[AFD + '/afdEndpoints/ep-shared/routes/billing-route'] = {
        'id': AFD + '/afdEndpoints/ep-shared/routes/billing-route', 'name': 'billing-route',
        'properties': {'patternsToMatch': ['/billing/*'],
                       'originGroup': {'id': AFD + '/originGroups/billing-og'}}}
    arm[AGW] = {'id': AGW, 'name': 'agw-shared', 'type': 'Microsoft.Network/applicationGateways',
                'properties': {'sku': {'name': 'WAF_v2'},
                               'httpListeners': [{'id': AGW + '/httpListeners/billing-listener',
                                                  'name': 'billing-listener',
                                                  'properties': {'hostName': 'billing.example'}}],
                               'requestRoutingRules': [{'id': AGW + '/requestRoutingRules/billing-rule',
                                                        'name': 'billing-rule',
                                                        'properties': {'priority': 100}}]}}
    return arm


def shared_release():
    """Release 501: what the product's deploy did to the shared estate, as its evidence records it."""
    arm = base_shared()
    before = copy.deepcopy(arm)
    nodes = []
    new_rule = rule('shop-allow-https', 300, 443, stamp('501'))
    old = arm[NSG + '/securityRules/shop-deny-legacy']
    mod = copy.deepcopy(old)
    mod['properties']['priority'], mod['properties']['description'] = 305, stamp('501')
    og = {'id': AFD + '/originGroups/shop-og', 'name': 'shop-og',
          'properties': {'healthProbeSettings': {'probePath': '/health'}}}
    route = {'id': AFD + '/afdEndpoints/ep-shared/routes/shop-route', 'name': 'shop-route',
             'properties': {'patternsToMatch': ['/shop/*'], 'originGroup': {'id': og['id']}}}
    listener = {'id': AGW + '/httpListeners/shop-listener', 'name': 'shop-listener',
                'properties': {'hostName': 'shop.example'}}
    nodes.append({'id': new_rule['id'], 'action': 'CREATED', 'prior': None, 'post': new_rule})
    nodes.append({'id': mod['id'], 'action': 'MODIFIED', 'prior': old, 'post': mod})
    nodes.append({'id': og['id'], 'action': 'CREATED', 'prior': None, 'post': og})
    nodes.append({'id': route['id'], 'action': 'CREATED', 'prior': None, 'post': route,
                  'depends_on': [og['id']]})
    nodes.append({'id': listener['id'], 'action': 'CREATED', 'prior': None, 'post': listener})
    for n in nodes[:4]:
        arm[n['id']] = copy.deepcopy(n['post'])
    arm[AGW]['properties']['httpListeners'].append(copy.deepcopy(listener))
    return before, arm, nodes


def stable_release(run, with_db=False):
    """A release that changed the product's stable resources (and, without a database, one NSG rule)."""
    arm = base_shared()
    app0 = {'id': APP, 'name': 'app-shop', 'type': 'Microsoft.Web/sites',
            'tags': {'release_ownership_stamp': stamp('300')},
            'properties': {'defaultHostName': HOST,
                           'siteConfig': {'linuxFxVersion': 'DOCKER|registry.example/shop@sha256:' + '1' * 64,
                                          'appSettings': [{'name': 'MODE', 'value': 'v1'}]}}}
    kv0 = {'id': KV, 'name': 'kv-shop', 'type': 'Microsoft.KeyVault/vaults',
           'tags': {'release_ownership_stamp': stamp('300')},
           'properties': {'vaultUri': 'https://kv-shop.vault.example/', 'softDeleteRetentionInDays': 7}}
    st0 = {'id': ST, 'name': 'stshopstatic', 'type': 'Microsoft.Storage/storageAccounts',
           'tags': {'release_ownership_stamp': stamp('300')},
           'properties': {'minimumTlsVersion': 'TLS1_0'}}
    db0 = {'id': DB, 'name': 'shopdb', 'type': 'Microsoft.Sql/servers/databases',
           'tags': {'release_ownership_stamp': stamp('300')},
           'sku': {'name': 'S0'}, 'properties': {'maxSizeBytes': 1073741824}}
    for b in (app0, kv0, st0) + ((db0,) if with_db else ()):
        arm[b['id']] = copy.deepcopy(b)
    nodes = []

    def modify(b, change):
        post = copy.deepcopy(b)
        change(post)
        post['tags'] = {'release_ownership_stamp': stamp(run)}
        nodes.append({'id': b['id'], 'action': 'MODIFIED', 'prior': copy.deepcopy(b), 'post': post})
        arm[b['id']] = copy.deepcopy(post)

    def app_change(p):
        p['properties']['siteConfig']['appSettings'] = [
            {'name': 'MODE', 'value': 'v2'},
            {'name': 'DB_PASSWORD', 'value': '@Microsoft.KeyVault(SecretUri=https://kv-shop.vault.example/secrets/db)'}]
        if with_db:
            p['properties']['siteConfig']['appSettings'].append({'name': 'SqlDatabaseId', 'value': DB})
    modify(app0, app_change)
    if with_db:
        modify(db0, lambda p: p['properties'].update(maxSizeBytes=2147483648))
    else:
        modify(kv0, lambda p: p['properties'].update(softDeleteRetentionInDays=90))
        modify(st0, lambda p: p['properties'].update(minimumTlsVersion='TLS1_2'))
        r = rule('shop-allow-https', 300, 443, stamp(run))
        nodes.append({'id': r['id'], 'action': 'CREATED', 'prior': None, 'post': r})
        arm[r['id']] = copy.deepcopy(r)
    return arm, nodes


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def others_at_deploy(arm, nodes):
    """What the deployer records of the OTHER entries in the shared resources it touched, as it left
    them: {entry id: sha256 of the canonical body} -- so a rollback can tell that another product
    has since moved its own entry."""
    import hashlib
    mine = set(n['id'].lower() for n in nodes)
    out = {}
    for k, v in arm.items():
        if k.startswith((NSG + '/', AFD + '/')) and k.lower() not in mine:
            out[k] = hashlib.sha256(canon(v).encode('utf-8')).hexdigest()
    for coll in ('httpListeners', 'requestRoutingRules'):
        for e in ((arm.get(AGW) or {}).get('properties') or {}).get(coll) or []:
            if e['id'].lower() not in mine:
                out[e['id']] = hashlib.sha256(canon(e).encode('utf-8')).hexdigest()
    return out


class World(object):
    def __init__(self, arm, evidence):
        self.dir = tempfile.mkdtemp(prefix='rollback-deps-')
        self.state = os.path.join(self.dir, 'state.json')
        self.log = os.path.join(self.dir, 'calls.jsonl')
        self.evidence = os.path.join(self.dir, 'evidence')
        os.makedirs(self.evidence)
        self.write({'arm': arm, 'healthy_hosts': [HOST]})
        io.open(self.log, 'w').close()
        self.bin = W.stub_bin(self.state, self.log)
        for run, nodes in evidence:
            d = os.path.join(self.evidence, 'deploy-evidence-%s-1' % run)
            os.makedirs(d)
            io.open(os.path.join(d, 'resources.json'), 'w', encoding='utf-8').write(json.dumps({
                'schema_version': 1, 'release_id': 'run-%s-1' % run, 'product': 'shop',
                'target': {'resource_group': 'rg-a', 'name': 'shop'},
                'app_url': 'https://%s' % HOST, 'nodes': nodes,
                'others_at_deploy': others_at_deploy(arm, nodes)}))
            io.open(os.path.join(d, 'outcome.json'), 'w', encoding='utf-8').write(
                json.dumps({'deployment_outcome': 'DEPLOY_HEALTHY'}))

    def write(self, s):
        io.open(self.state, 'w', encoding='utf-8').write(json.dumps(s))

    def read(self):
        return json.load(io.open(self.state, encoding='utf-8'))

    def calls(self):
        return [json.loads(x) for x in io.open(self.log, encoding='utf-8') if x.strip()]

    def sequence(self, runs, mutate=None):
        if mutate:
            s = self.read()
            mutate(s['arm'])
            self.write(s)
        io.open(self.log, 'w').close()
        seq = os.path.join(self.dir, 'sequence.json')
        io.open(seq, 'w', encoding='utf-8').write(json.dumps({'sequence_id': 'deps', 'steps': [
            {'deployment': 'run %s' % r, 'run_id': r, 'run_attempt': '1', 'adapter': 'arm'} for r in runs]}))
        fx = os.path.join(self.dir, 'e2e.py')
        io.open(fx, 'w', encoding='utf-8').write(E2E)
        e2e_log = os.path.join(self.dir, 'e2e.log')
        io.open(e2e_log, 'w').close()
        out = os.path.join(self.dir, 'record.json')
        summ = os.path.join(self.dir, 'summary.md')
        io.open(summ, 'w').close()
        env = dict(os.environ)
        env.update({'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1', 'fake_az_state': self.state,
                    'fake_az_log': self.log, 'e2e_log': e2e_log,
                    'PATH': self.bin + os.pathsep + env.get('PATH', ''),
                    'health_retries'.upper(): '1', 'health_interval_seconds'.upper(): '0'})
        for k in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
            env.pop(k, None)
        p = subprocess.run([sys.executable, ENGINE, 'run', '--sequence', seq, '--evidence-root',
                            self.evidence, '--work', os.path.join(self.dir, 'work'), '--out', out,
                            '--e2e-command', '"%s" "%s"' % (sys.executable, fx),
                            '--test-period-seconds', '1', '--locked-target', 'rg-a/shop',
                            '--summary', summ], env=env, capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        try:
            record = json.load(io.open(out, encoding='utf-8'))
        except (OSError, ValueError):
            record = {'result': None, 'why': (p.stdout + p.stderr)[-1500:], 'steps': []}
        self.out = out
        e2e = [x for x in io.open(e2e_log, encoding='utf-8').read().split('\n') if x]
        return p.returncode, record, e2e, io.open(summ, encoding='utf-8').read()

    def close(self):
        shutil.rmtree(self.bin, ignore_errors=True)
        shutil.rmtree(self.dir, ignore_errors=True)


def writes(calls):
    """-> [(method, resource id)] of every mutating ARM call."""
    out = []
    for c in calls:
        if c[:2] == ['az', 'rest']:
            a = c[2:]
            m = a[a.index('--method') + 1] if '--method' in a else 'get'
            u = a[a.index('--url') + 1] if '--url' in a else ''
            if m.lower() in ('put', 'patch', 'delete'):
                out.append((m.lower(), u.split('?')[0]))
    return out


def review(record, i=0):
    return ((record.get('steps') or [{}] * (i + 1))[i] or {}).get('dependency_review') or {}


def main():
    fails = []

    def check(c, m):
        if not c:
            fails.append(m)

    try:
        import yaml
        import rollback_sequence as rs
        import rollback_dependencies as rd
        import rollback_hold as rh
    except Exception as exc:  # noqa: BLE001
        print('FAIL: the dependency-aware rollback does not exist: %s' % exc)
        return 1
    worlds = []
    try:
        # ---- D5 the registry ------------------------------------------------------------------------
        reg = yaml.safe_load(io.open(os.path.join(ROOT, 'rollback-resource-classes.yaml'), encoding='utf-8'))
        classes = set((v or {}).get('class') for v in (reg.get('types') or {}).values())
        check(classes == {'SHARED_MULTI_CONFIG', 'STABLE'},
              'D5: the registry classes are %r, not exactly the two' % classes)
        for t, c in (('Microsoft.Network/networkSecurityGroups', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Cdn/profiles', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Network/applicationGateways', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Network/firewallPolicies', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Network/routeTables', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Network/dnsZones', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.ApiManagement/service', 'SHARED_MULTI_CONFIG'),
                     ('Microsoft.Web/sites', 'STABLE'), ('Microsoft.App/containerApps', 'STABLE'),
                     ('Microsoft.Sql/servers/databases', 'STABLE'), ('Microsoft.Storage/storageAccounts', 'STABLE'),
                     ('Microsoft.KeyVault/vaults', 'STABLE'), ('Microsoft.Compute/virtualMachines', 'STABLE'),
                     ('Microsoft.ContainerInstance/containerGroups', 'STABLE'),
                     ('Microsoft.DocumentDB/databaseAccounts', 'STABLE')):
            got = rd.classify(rd.load_registry(), t)
            check(got == c, 'D5: %s is classed %r, not %s' % (t, got, c))

        # ---- D1 shared: only other products moved ---------------------------------------------------
        before, deployed, nodes = shared_release()
        w = World(deployed, [('501', nodes)])
        worlds.append(w)

        def billing_changed(arm):
            arm[NSG + '/securityRules/billing-allow-8443']['properties']['sourceAddressPrefix'] = '10.9.0.0/16'
        rc, r, e2e, summ = w.sequence(['501'], mutate=billing_changed)
        final = w.read()['arm']
        rv = review(r)
        print('  D1 %s %s basis=%s writes=%s' % (r.get('result'), rv.get('outcome'),
                                                 ((r.get('steps') or [{}])[0].get('eligibility') or {}).get('basis'),
                                                 len(writes(w.calls()))))
        check(rc == 0 and r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED',
              'D1: a shared-config rollback with only other products moved was not verified: %r -- %s'
              % (r.get('result'), r.get('why')))
        check(rv.get('outcome') == 'ROLLBACK_SCOPED_TO_PRODUCT_CONFIG',
              'D1: the outcome is %r, not ROLLBACK_SCOPED_TO_PRODUCT_CONFIG' % rv.get('outcome'))
        check(((r.get('steps') or [{}])[0].get('eligibility') or {}).get('basis') == 'ELIGIBLE_OWNED_PART_SEPARABLE',
              'D1: another product moved its own entry, so the basis is the owned part')
        expect = copy.deepcopy(before)
        expect[NSG + '/securityRules/billing-allow-8443']['properties']['sourceAddressPrefix'] = '10.9.0.0/16'
        check(canon(final) == canon(expect),
              'D1: the shared estate is not back to its state before the release with the other '
              'product\'s change kept: differs at %s' % sorted(k for k in set(final) | set(expect)
                                                            if canon(final.get(k)) != canon(expect.get(k))))
        mine = set(n['id'].lower() for n in nodes) | {AGW.lower()}
        check(all(u.lower() in mine for _m, u in writes(w.calls())) and writes(w.calls()),
              'D1: a PUT or DELETE reached something that is not the product\'s entry (or its '
              'inline parent): %s' % [u for _m, u in writes(w.calls()) if u.lower() not in mine])
        others = rv.get('others_untouched') or []
        check(others and all(o.get('identical') for o in others) and
              {NSG + '/securityRules/billing-allow-8443', AFD + '/afdEndpoints/ep-shared/routes/billing-route',
               AGW + '/httpListeners/billing-listener'} <= set(o.get('id') for o in others),
              'D1: the record does not show every other product\'s entry read back byte-identical: %r' % others)

        # ---- D2 a foreign change to one of the product's own NSG rules -------------------------------
        w = World(deployed, [('501', nodes)])
        worlds.append(w)
        mine_rule = NSG + '/securityRules/shop-allow-https'

        def foreign_rule(arm):
            arm[mine_rule]['properties']['sourceAddressPrefix'] = '*'
        rc, r, e2e, summ = w.sequence(['501'], mutate=foreign_rule)
        final = w.read()['arm']
        rv = review(r)
        st = (r.get('steps') or [{}])[0]
        marks = dict((n['id'], n['mark']) for n in rv.get('nodes') or [])
        print('  D2 %s %s step=%s left=%s' % (r.get('result'), rv.get('outcome'), st.get('step_result'),
                                              [x.get('id', '').rsplit('/', 1)[-1] for x in rv.get('not_reversed') or []]))
        check(rv.get('outcome') == 'ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT' and
              st.get('step_result') == 'ROLLBACK_STEP_PARTIAL' and
              r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_DEPENDENCY_CONFLICT' and
              r.get('rollback_state') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and rc == 1,
              'D2: a foreign change to the product\'s own rule was not a partial rollback stopped for a '
              'human: %r %r %r %r' % (r.get('result'), rv.get('outcome'), st.get('step_result'), r.get('rollback_state')))
        check(final[mine_rule]['properties']['sourceAddressPrefix'] == '*' and
              final[NSG + '/securityRules/shop-deny-legacy']['properties']['priority'] == 305,
              'D2: the cross-edited rule, or the product\'s other rule in the same NSG, was touched')
        check(AFD + '/afdEndpoints/ep-shared/routes/shop-route' not in final and
              AFD + '/originGroups/shop-og' not in final and
              [x['name'] for x in final[AGW]['properties']['httpListeners']] == ['billing-listener'],
              'D2: the independent Front Door and gateway entries were not reversed')
        check(marks.get(mine_rule) == 'changed-by-other',
              'D2: the cross-edited rule is not marked changed-by-other: %r' % marks)
        left = dict((x['id'], x.get('reason', '')) for x in rv.get('not_reversed') or [])
        check('another actor' in left.get(mine_rule, '') and
              'priority' in left.get(NSG + '/securityRules/shop-deny-legacy', ''),
              'D2: the reasons do not name the other actor and the priority coupling: %r' % left)
        check(not rs.validate(r), 'D2: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- D3 an App Service changed by another actor ---------------------------------------------
        arm, nodes3 = stable_release('601')
        w = World(arm, [('601', nodes3)])
        worlds.append(w)

        def foreign_app(a):
            a[APP]['properties']['siteConfig']['linuxFxVersion'] = 'DOCKER|registry.example/other@sha256:' + 'f' * 64
            a[APP]['tags'] = {'changed_by': 'another-pipeline'}
        rc, r, e2e, summ = w.sequence(['601'], mutate=foreign_app)
        final = w.read()['arm']
        rv = review(r)
        st = (r.get('steps') or [{}])[0]
        marks = dict((n['id'], n['mark']) for n in rv.get('nodes') or [])
        edges = set((e['from'], e['to']) for e in rv.get('edges') or [])
        print('  D3 %s %s full=%s marks=%s' % (r.get('result'), rv.get('outcome'), rv.get('full_rollback'),
                                               dict((k.rsplit('/', 1)[-1], v) for k, v in marks.items())))
        check(rv.get('outcome') == 'ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT' and
              rv.get('full_rollback') == 'refused' and rv.get('rollback_state') == 'ROLLBACK_REQUIRES_HUMAN_DECISION',
              'D3: an App Service changed by another actor did not refuse a FULL rollback and do a '
              'partial one: %r' % dict((k, rv.get(k)) for k in ('outcome', 'full_rollback', 'rollback_state')))
        check(final[ST]['properties']['minimumTlsVersion'] == 'TLS1_0' and NSG + '/securityRules/shop-allow-https' not in final,
              'D3: the independent storage account and NSG rule were not reversed')
        check(final[APP]['tags'] == {'changed_by': 'another-pipeline'} and
              final[KV]['properties']['softDeleteRetentionInDays'] == 90,
              'D3: the App Service, or the Key Vault it depends on, was touched')
        check(marks.get(APP) == 'changed-by-other' and marks.get(KV) == 'changed-by-this-release' and
              marks.get(ST) == 'changed-by-this-release' and (APP, KV) in edges,
              'D3: the graph does not mark the nodes or carry the app -> vault edge: %r %r' % (marks, edges))
        left = dict((x['id'], x.get('reason', '')) for x in rv.get('not_reversed') or [])
        check(APP in left and KV in left and 'depends' in left.get(KV, ''),
              'D3: the nodes left are not listed with reasons: %r' % left)
        gdir = os.path.join(w.dir, 'work', 'step-01')
        try:
            g = json.load(io.open(os.path.join(gdir, 'dependency-graph.json'), encoding='utf-8'))
            mmd = io.open(os.path.join(gdir, 'dependency-graph.mmd'), encoding='utf-8').read()
        except (OSError, ValueError) as exc:
            g, mmd = {}, ''
            fails.append('D3: the dependency graph was not written to the step\'s evidence: %s' % exc)
        check(g.get('nodes') and 'graph' in mmd and 'app-shop' in mmd and '-->' in mmd,
              'D3: the evidence graph is empty or not Mermaid: %r' % mmd[:200])
        check('```mermaid' in summ and 'app-shop' in summ and 'changed by other' in summ.lower(),
              'D3: the run summary does not show the dependency graph: %s' % summ[-600:])
        check(len(e2e) == 2, 'D3: the partial state did not get its test period (start and end): %d' % len(e2e))
        check(not rs.validate(r), 'D3: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- D4 a database changed by another actor -------------------------------------------------
        arm, nodes4 = stable_release('701', with_db=True)
        w = World(arm, [('701', nodes4)])
        worlds.append(w)
        rc, r, e2e, summ = w.sequence(['701'], mutate=lambda a: a[DB].update(sku={'name': 'P2'}))
        rv = review(r)
        st = (r.get('steps') or [{}])[0]
        print('  D4 %s %s step=%s writes=%d' % (r.get('result'), rv.get('outcome'), st.get('step_result'),
                                                len(writes(w.calls()))))
        check(rv.get('outcome') == 'ROLLBACK_REFUSED_DEPENDENCY_CONFLICT' and not writes(w.calls()) and
              st.get('step_result') == 'ROLLBACK_STEP_INELIGIBLE' and
              (st.get('eligibility') or {}).get('disposition') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and
              r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_DEPENDENCY_CONFLICT',
              'D4: a database changed by another actor did not refuse every reversal: %r %r %r writes=%s'
              % (r.get('result'), rv.get('outcome'), st.get('step_result'), writes(w.calls())))
        check(rv.get('nodes') and rv.get('mermaid') and (APP, DB) in set((e['from'], e['to']) for e in rv.get('edges') or []),
              'D4: no dependency graph (app -> database) was emitted with the refusal')
        check(not e2e, 'D4: tests ran although nothing was rolled back')
        check(not rs.validate(r), 'D4: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- D6 the marker -------------------------------------------------------------------------
        hw = Hold(w.dir)
        worlds.append(hw)
        d1_record = World(deployed, [('501', nodes)])
        worlds.append(d1_record)
        rc, r, _e, _s = d1_record.sequence(['501'])
        check(r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED', 'D6: the rollback the marker is for failed')
        rc, out = hw.marker(d1_record.out, d1_record.evidence)
        mk = hw.read_marker()
        changed = dict((c.get('id'), c) for c in mk.get('changed') or [])
        print('  D6 marker rc=%d rolled_back=%s changed=%d' % (
            rc, [x.get('release') for x in mk.get('rolled_back') or []], len(changed)))
        check(rc == 0 and mk.get('rollback_run_id') == '900' and
              [x.get('release') for x in mk.get('rolled_back') or []] == ['run-501-1'] and
              (mk.get('rolled_back') or [{}])[0].get('commit') == C_ROLLED and
              mk.get('target', {}).get('name') == 'shop',
              'D6: the rollback did not write a marker naming its run, target and the rolled-back '
              'release with its commit: %s %r' % (out[-400:], mk))
        check((changed.get(AFD + '/afdEndpoints/ep-shared/routes/shop-route') or {}).get('after') == 'absent' and
              (changed.get(NSG + '/securityRules/shop-deny-legacy') or {}).get('after') == 'restored',
              'D6: the marker does not record what the rollback removed and what it restored: %r' % changed)
        hw.publish_marker()

        # ---- D7 the dependency check on an incoming deploy ----------------------------------------
        ROUTE = AFD + '/afdEndpoints/ep-shared/routes/shop-route'
        BILLING = AFD + '/afdEndpoints/ep-shared/routes/billing-route'
        cases = [
            ('built on the rolled-back commit', C_ON_TOP, BEFORE, [], 'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY', 1,
             ['run-501-1', C_ROLLED[:12]]),
            ('depends on a route the rollback removed', C_UNRELATED, BEFORE, [ROUTE],
             'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY', 1, ['shop-route', 'no longer exists']),
            ('depends on a rule the rollback restored', C_UNRELATED, BEFORE,
             ['nsg-shared/securityRules/shop-deny-legacy'],
             'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY', 1, ['shop-deny-legacy', '305 -> 310']),
            ('depends only on what the rollback left alone', C_UNRELATED, BEFORE, [BILLING],
             'DEPLOY_NO_ROLLBACK_DEPENDENCY', 0, ['no dependency']),
            ('based after the rollback', C_ON_TOP, AFTER, [ROUTE], 'ROLLBACK_CHECK_NOT_REQUIRED', 0, []),
        ]
        for label, commit, when, deps, want, want_rc, says in cases:
            rc, doc, summ = hw.check(commit, when, deps)
            print('  D7 %-48s %s rc=%d' % (label[:48], doc.get('rollback_check'), rc))
            check(doc.get('rollback_check') == want and rc == want_rc,
                  'D7: %s -> %r rc=%d, not %s rc=%d %s' % (label, doc.get('rollback_check'), rc, want, want_rc,
                                                          doc.get('out', '')))
            for s in says:
                check(s in summ, 'D7: %s: the report does not say %r: %s' % (label, s, summ[-700:]))
            if want == 'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY':
                check('900' in summ and doc.get('dependencies') and
                      (doc.get('rollback') or {}).get('run_id') == '900',
                      'D7: %s: the report does not name the rollback and its dependencies: %r' % (label, doc))
        rc, doc, summ = hw.check(C_UNRELATED, BEFORE, [], image=IMG_ROLLED)
        print('  D7 %-48s %s rc=%d' % ('brings back a rolled-back image', doc.get('rollback_check'), rc))
        check(doc.get('rollback_check') == 'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY' and rc == 1 and IMG_ROLLED in summ,
              'D7: a deploy of the rolled-back image was not refused: %r' % doc.get('rollback_check'))
        for what in ('listing', 'compare'):
            rc, doc, _s = hw.check(C_ON_TOP, BEFORE, [], unreadable=what)
            print('  D7 %-48s %s rc=%d' % ('unreadable ' + what, doc.get('rollback_check'), rc))
            check(doc.get('rollback_check') == 'ROLLBACK_DEPENDENCY_CHECK_INCOMPLETE' and rc == 1,
                  'D7: an unreadable %s did not refuse as INCOMPLETE: %r' % (what, doc.get('rollback_check')))

        # ---- D8 the deploy reusables as shipped ------------------------------------------------------
        import _deploy_steps as DS
        rb = DS.load(os.path.join(ROOT, '.github', 'workflows', 'reusable-rollback-sequence.yml'))
        rsteps = rb['jobs']['rollback']['steps']
        mk_i = [i for i, s in enumerate(rsteps)
                if 'rollback_hold.py' in str(s.get('run', '')) and ' marker' in str(s.get('run', ''))]
        up = [s for s in rsteps if 'upload-artifact' in str(s.get('uses', ''))
              and 'marker' in str((s.get('with') or {}).get('name', ''))]
        check(mk_i and up, 'D8: the rollback reusable does not write and upload the rollback marker')
        for path in (DS.APPSERVICE, DS.CONTAINERAPP):
            doc = DS.load(path)
            names = [s.get('name') for s in DS.steps(doc)]
            hold_i = [i for i, s in enumerate(DS.steps(doc)) if 'rollback_hold.py" check' in str(s.get('run', ''))]
            base = os.path.basename(path)
            check('declared_dependencies' in DS.inputs_of(doc) and 'acknowledge_rollback' not in DS.inputs_of(doc),
                  'D8: %s does not take declared_dependencies (and must have no override input)' % base)
            check(hold_i and 'Azure login (OIDC)' in names and hold_i[0] < names.index('Azure login (OIDC)'),
                  'D8: %s does not run the rollback dependency check before login' % base)
            check((doc.get('permissions') or {}).get('actions') == 'read',
                  'D8: %s cannot read the rollback marker (actions: read)' % base)
            hold_name = names[hold_i[0]] if hold_i else ''
            res, final, calls, summ = hw.deploy(path, C_ON_TOP)
            order = dict(res['order'])
            route = res['steps'].get('posture', {}).get('outputs', {}).get('routing_result')
            print('  D8 %s dependent: check=%s az calls=%d route=%s' % (
                base, order.get(hold_name), len([c for c in calls if c[0] == 'az']), route))
            check(order.get(hold_name) == 'failure' and not [c for c in calls if c[0] == 'az'] and route == 'BLOCKED',
                  'D8: %s, built on the rolled-back release, did not stop at the check before login, '
                  'routing BLOCKED: %r' % (base, res['order']))
            check('DEPLOY_REFUSED_ROLLBACK_DEPENDENCY' in summ and 'run-501-1' in summ and
                  ((res.get('evidence') or {}).get('rollback-check.json') or {}).get('rollback_check') ==
                  'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY',
                  'D8: %s does not report the refusal in its summary and evidence' % base)
            res, final, calls, summ = hw.deploy(path, C_UNRELATED)
            print('  D8 %s not dependent: failed=%s check=%s' % (base, res['failed'],
                                                                dict(res['order']).get(hold_name)))
            check(not res['failed'] and dict(res['order']).get(hold_name) == 'success',
                  'D8: %s, not dependent on the rollback, did not deploy: %s' % (base, res['log'][-1500:]))
            check(((res.get('evidence') or {}).get('rollback-check.json') or {}).get('rollback_check') ==
                  'DEPLOY_NO_ROLLBACK_DEPENDENCY' and 'no dependency' in summ,
                  'D8: %s does not keep the note that the check ran and found none' % base)
    finally:
        for w in worlds:
            w.close()
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: shared multi-config resources roll back only the product\'s entries, every other entry '
          'read back byte-identical; a cross-edit of the product\'s own entry, or a stable resource '
          'changed by another actor, gets a dependency review: a refused full rollback, a partial '
          'rollback of the independent parts or none, with reasons and the graph (JSON and Mermaid) in '
          'the record, the evidence and the summary; ROLLBACK_REQUIRES_HUMAN_DECISION is emitted; a '
          'deploy whose base predates a rollback of its target is checked for dependencies on what '
          'was rolled back (lineage, declared resources and entries, images) and refused with a '
          'report when it has any, deployed with a note when it has none, and refused when the check '
          'cannot be completed; both deploy reusables run the check before login.')
    return 0


# --------------------------------------------------------------------------- the check's world
C_ROLLED = 'c0ffee' + '0' * 34      # the rolled-back release's commit
C_ON_TOP = 'beef01' + '0' * 34      # a later commit that contains it
C_UNRELATED = 'face02' + '0' * 34   # a commit that does not
BEFORE, AFTER = '2026-10-23T09:00:00Z', '2026-10-23T11:00:00Z'
DONE = '2026-10-23T10:00:00Z'
IMG_ROLLED = 'registry.example/shop@sha256:' + '5' * 64


def file_url(path):
    return 'file:///' + path.replace(os.sep, '/').lstrip('/')


class Hold(object):
    """A recorded GitHub API (file://, the same stand-in the deploy proofs use for environments)."""

    def __init__(self, parent):
        self.dir = tempfile.mkdtemp(prefix='rollback-check-')
        self.api = os.path.join(self.dir, 'api')
        self.repo = os.path.join(self.api, 'repos', 'o', 'r')
        os.makedirs(os.path.join(self.repo, 'environments'))
        self.put('actions/artifacts', {'total_count': 0, 'artifacts': []})
        self.put('actions/runs/501', {'id': 501, 'head_sha': C_ROLLED})
        self.put('environments/env', getattr(W, 'protected_environment'.upper()))
        for c in (C_ON_TOP, C_UNRELATED):
            self.put('compare/%s...%s' % (C_ROLLED, c), {'status': 'ahead' if c == C_ON_TOP else 'diverged'})
        self.marker_path = os.path.join(self.dir, 'marker', 'marker.json')

    def put(self, rel, doc):
        p = os.path.join(self.repo, *rel.split('/'))
        if not os.path.isdir(os.path.dirname(p)):
            os.makedirs(os.path.dirname(p))
        io.open(p, 'w', encoding='utf-8').write(json.dumps(doc))

    def env(self):
        e = dict(os.environ)
        e.update({'GITHUB_API_URL': file_url(self.api), 'GITHUB_REPOSITORY': 'o/r', 'GH_TOKEN': ''})
        return e

    def marker(self, record, evidence):
        p = subprocess.run([sys.executable, HOLD, 'marker', '--record', record, '--evidence-root', evidence,
                            '--environment', 'env', '--resource-group', 'rg-a', '--name', 'shop',
                            '--run-id', '900', '--run-attempt', '1', '--completed-at', DONE,
                            '--out', self.marker_path], env=self.env(), capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        return p.returncode, p.stdout + p.stderr

    def read_marker(self):
        try:
            return json.load(io.open(self.marker_path, encoding='utf-8'))
        except (OSError, ValueError):
            return {}

    def publish_marker(self):
        """The marker as the rollback reusable uploads it; the rolled-back release also carried an image."""
        import rollback_hold as rh
        mk = self.read_marker()
        if mk.get('rolled_back'):
            mk['rolled_back'][0]['images'] = [IMG_ROLLED]
        z = os.path.join(self.dir, 'zips', '1.zip')
        os.makedirs(os.path.dirname(z))
        with zipfile.ZipFile(z, 'w') as zf:
            zf.writestr('marker.json', json.dumps(mk))
        self.put('actions/artifacts', {'total_count': 1, 'artifacts': [
            {'id': 1, 'name': rh.marker_name('env', 'rg-a', 'shop'), 'expired': False, 'created_at': DONE,
             'archive_download_url': file_url(z)}]})

    def check(self, commit, when, deps, image='registry.example/shop@sha256:' + '2' * 64, unreadable=''):
        self.put('commits/%s' % commit, {'sha': commit, 'commit': {'committer': {'date': when}}})
        moved = {}
        if unreadable:
            rel = {'listing': 'actions/artifacts', 'compare': 'compare/%s...%s' % (C_ROLLED, commit)}[unreadable]
            p = os.path.join(self.repo, *rel.split('/'))
            moved[p] = io.open(p, encoding='utf-8').read()
            os.remove(p)
        out = os.path.join(self.dir, 'check.json')
        summ = os.path.join(self.dir, 'check-summary.md')
        io.open(summ, 'w').close()
        if os.path.exists(out):
            os.remove(out)
        p = subprocess.run([sys.executable, HOLD, 'check', '--environment', 'env', '--resource-group',
                            'rg-a', '--name', 'shop', '--commit', commit, '--run-id', '777',
                            '--declared-dependencies', json.dumps(deps), '--image', image,
                            '--out', out, '--summary', summ], env=self.env(), capture_output=True,
                           text=True, encoding='utf-8', errors='replace')
        for path, body in moved.items():
            io.open(path, 'w', encoding='utf-8').write(body)
        try:
            doc = json.load(io.open(out, encoding='utf-8'))
        except (OSError, ValueError):
            doc = {'rollback_check': None, 'out': (p.stdout + p.stderr)[-800:]}
        return p.returncode, doc, io.open(summ, encoding='utf-8').read() + p.stdout

    def deploy(self, path, commit):
        """Run a deploy reusable as shipped, with a marker for its target in the recorded API."""
        cont = path.endswith('containerapp.yml')
        inputs = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
                      resource_group='rg-a', acr_login_server=W.REG, image_repository=W.REPO,
                      image_digest=W.NEW, cloud='commercial', health_path='/health', health_retries=1,
                      health_interval_seconds=0, rollback_on_failure=True, version_metadata='',
                      declared_dependencies='')
        if cont:
            inputs['containerapp_name'] = 'shop'
            state = W.containerapp_state(mode='Multiple')
            state['containerapp']['name'] = 'shop'
        else:
            inputs.update(webapp_name='shop', slot='', swap_on_healthy=False)
            state = W.appservice_state()
            state['webapp']['name'] = 'shop'
        self.put('commits/%s' % commit, {'sha': commit, 'commit': {'committer': {'date': BEFORE}}})
        api_files = {}
        for dp, _dn, fns in os.walk(self.api):
            for f in fns:
                rel = os.path.relpath(os.path.join(dp, f), self.api).replace(os.sep, '/')
                api_files[rel] = io.open(os.path.join(dp, f), encoding='utf-8').read()
        res, final, calls = W.run_world(path, inputs, state, api_files=api_files,
                                        env_extra={'github_sha'.upper(): commit, 'github_run_id'.upper(): '777',
                                                   'github_run_attempt'.upper(): '1'})
        return res, final, calls, res.get('summary', '')

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
