#!/usr/bin/env python3
"""Under the seam, a deploy writes no setting the landing zone owns, and never swaps a non-sticky
landing-zone setting into production. (OF-5 K-6; KDEC-030 R3, "One owner per field")

WHY THIS EXISTS

    Every app setting and environment key has exactly one owner (R3). An unassigned key is the landing
    zone's (its item 84); the kit owns only the env key release_ownership_stamp and any key the hand-off
    assigns it in KIT_SETTING_KEYS (empty by default). Two ways the kit could still write a
    landing-zone key were owed:

      SEAM_SETTING_OWNERSHIP_CONFLICT   a key the kit would write that it does not own, or a key both
                                        sides claim: KIT_SETTING_KEYS naming a key the landing zone has
                                        made slot-sticky (sticky configuration is the landing zone's,
                                        R1) or a secret-backed environment key (secrets are the landing
                                        zone's), or a KIT_SETTING_KEYS value that is not a list of names
      SEAM_SWAP_MOVES_LZ_SETTING        an App Service swap would carry a non-sticky landing-zone setting
                                        (or connection string) that differs between the slot and
                                        production -- a swap moves non-sticky settings with the slot

    Both are refused by a `seam` step after the capture and BEFORE the first mutation, only when the
    environment opts into the KDEC-030 seam (KIT_TARGET_LEASE_ACCOUNT), exactly as the lease is. A read
    that fails is SEAM_OWNERSHIP_NOT_ESTABLISHED, a refusal. Values are never printed: keys are named,
    values compared by digest.

CASES
    S1  decide(): the pure rules, every outcome by name
    S2  all three deploy reusables run the seam step (id seam) after capture/capability and before the
        lease `begin` and the first mutation, only when the lease is on; the posture routes a refusal
        BLOCKED; the job reads KIT_SETTING_KEYS from its environment (the Static Web Apps reusable since
        integrate/r8, KDEC-030 D-4 parity: its first mutation is the preview deploy, and its seam runs
        static_site_contract.py seam -- tests/prove_deploy_staticwebapp.py J11 runs it)
    S3  the App Service job AS SHIPPED (stub cloud): a non-sticky LZ setting differing between the slot
        and production -> SEAM_SWAP_MOVES_LZ_SETTING, zero mutating calls; the same key sticky -> held;
        a differing connection string -> refused; KIT_SETTING_KEYS naming a sticky key -> CONFLICT;
        equal non-sticky settings -> held (control); the settings unreadable -> NOT_ESTABLISHED
    S4  the Container Apps job AS SHIPPED: KIT_SETTING_KEYS naming a secret-backed env key -> CONFLICT,
        zero mutating calls; a plain key -> held
    S5  the lease off: the seam step does not run, nothing changes (control)

EXIT 0 proven   1 a case failed   2 could not be checked
"""
import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _workflow_runner as W  # noqa: E402

FAILS = []
WFS = {'appservice': W.D.APPSERVICE, 'containerapp': W.D.CONTAINERAPP}
# The seam's wiring is checked on every deploy reusable: (workflow, first mutating step id, the seam command).
WIRING = {'appservice': (W.D.APPSERVICE, 'deploy', 'deploy_contract.py" seam'),
          'containerapp': (W.D.CONTAINERAPP, 'deploy', 'deploy_contract.py" seam'),
          'staticwebapp': (os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-staticwebapp.yml'),
                           'deploy_preview', 'static_site_contract.py" seam')}
MUTATING = ('update', 'set', 'swap', 'restart', 'activate', 'deactivate', 'delete', 'create')


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def pure():
    import deploy_contract as dc
    d = dc.decide_seam
    ok = 'SEAM_OWNERSHIP_HELD'
    cases = [
        ('nothing assigned, nothing written', d('appservice', '', [], None, None, False), ok),
        ('a bad key list', d('appservice', 'A,B C;D', [], None, None, False), 'SEAM_OWNERSHIP_NOT_ESTABLISHED'),
        ('a kit key the LZ made sticky', d('appservice', 'feature_x',
                                           [{'name': 'feature_x', 'value': '1', 'slotSetting': True}], None, None, False),
         'SEAM_SETTING_OWNERSHIP_CONFLICT'),
        ('a kit key that is secret-backed', d('containerapp', 'DB_PASSWORD',
                                              [{'name': 'DB_PASSWORD', 'secretRef': 'db'}], None, None, False),
         'SEAM_SETTING_OWNERSHIP_CONFLICT'),
        ('a write outside the kit keys', d('appservice', '', [], None, None, False, planned=['MODE']),
         'SEAM_SETTING_OWNERSHIP_CONFLICT'),
        ('the stamp is the kit\'s own', d('containerapp', '', [], None, None, False,
                                         planned=['release_ownership_stamp']), ok),
        ('swap: a differing non-sticky LZ key', d('appservice', '', [{'name': 'MODE', 'value': 'a'}],
                                                  [{'name': 'MODE', 'value': 'b'}], ([], []), True),
         'SEAM_SWAP_MOVES_LZ_SETTING'),
        ('swap: a key only in the slot', d('appservice', '', [], [{'name': 'NEW', 'value': 'x'}], ([], []), True),
         'SEAM_SWAP_MOVES_LZ_SETTING'),
        ('swap: a differing sticky key', d('appservice', '', [{'name': 'MODE', 'value': 'a', 'slotSetting': True}],
                                           [{'name': 'MODE', 'value': 'b', 'slotSetting': True}], ([], []), True), ok),
        ('swap: a differing kit key', d('appservice', 'MODE', [{'name': 'MODE', 'value': 'a'}],
                                        [{'name': 'MODE', 'value': 'b'}], ([], []), True), ok),
        ('swap: a differing connection string', d('appservice', '', [], [],
                                                  ([{'name': 'Db', 'value': {'value': 'x'}}],
                                                   [{'name': 'Db', 'value': {'value': 'y'}}]), True),
         'SEAM_SWAP_MOVES_LZ_SETTING'),
        ('swap: production unreadable', d('appservice', '', None, [], ([], []), True), 'SEAM_OWNERSHIP_NOT_ESTABLISHED'),
    ]
    for label, got, want in cases:
        expect(got[0] == want, 'S1 %s -> %s (%s)' % (label, want, got[0]))
    got = d('appservice', '', [{'name': 'secret_thing', 'value': 'hunter2'}],
            [{'name': 'secret_thing', 'value': 'hunter3'}], ([], []), True)
    expect('hunter' not in got[1] and 'secret_thing' in got[1], 'S1 the key is named and the values are never shown')


def wiring():
    for name, (wf, mut, cmd) in sorted(WIRING.items()):
        doc = W.D.load(wf)
        steps = W.D.steps(doc)
        ids = [s.get('id') for s in steps]
        ok = 'seam' in ids
        expect(ok, 'S2 %s: a seam step exists' % name)
        if not ok:
            continue
        s = steps[ids.index('seam')]
        expect(mut in ids and ids.index('capability') < ids.index('seam') < ids.index('lease_begin') < ids.index(mut),
               'S2 %s: capability < seam < lease begin < the first mutation (%s)' % (name, mut))
        expect("env.KIT_TARGET_LEASE_ACCOUNT != ''" in str(s.get('if')), 'S2 %s: only when the seam is opted in' % name)
        expect(cmd in (s.get('run') or ''), 'S2 %s: it runs %s' % (name, cmd.replace('"', '')))
        jenv = W.D.job(doc).get('env') or {}
        expect(str(jenv.get('KIT_SETTING_KEYS')) == '${{ vars.KIT_SETTING_KEYS }}',
               'S2 %s: the job reads KIT_SETTING_KEYS from its environment' % name)
        post = next((x for x in steps if x.get('id') == 'posture'), {})
        expect('steps.seam.outcome' in str(post.get('env')) and 'seam_outcome'.upper() in (post.get('run') or ''),
               'S2 %s: the posture step reads and routes the seam outcome' % name)


LEASE = {'KIT_TARGET_LEASE_ACCOUNT': 'seamleasedev'}


def mutations(calls):
    return [c for c in calls if c[0] == 'az' and any(w in c[1:5] for w in MUTATING)]


def run_app(state, keys='', lease=True, slot='staging'):
    inputs = dict(github_environment='production', routing_result='PROCEED', environment_tier='dev',
                  resource_group='rg-a', webapp_name='web', acr_login_server=W.REG, image_repository=W.REPO,
                  image_digest=W.NEW, cloud='commercial', slot=slot, swap_on_healthy=True,
                  rollback_on_failure=True, health_path='/health', health_retries=1, health_interval_seconds=0)
    extra = dict(LEASE if lease else {}, KIT_SETTING_KEYS=keys)
    res, final, calls = W.run_world(WFS['appservice'], inputs, state, env_extra=extra)
    seam = res['steps'].get('seam') or {}
    return seam, res, mutations([c for c in calls]), calls


def appservice_cases():
    def st(prod=None, slot=None, sticky=(), cs=None):
        s = W.appservice_state()
        s['webapp']['slots']['production']['appsettings'] = dict(prod or {})
        s['webapp']['slots']['staging']['appsettings'] = dict(slot or {})
        s['webapp']['sticky'] = list(sticky)
        if cs:
            s['webapp']['slots']['production']['connectionstrings'] = cs[0]
            s['webapp']['slots']['staging']['connectionstrings'] = cs[1]
        return s
    for label, state, keys, want in (
            ('a non-sticky LZ setting differs', st({'MODE': 'prod'}, {'MODE': 'stage'}), '',
             'SEAM_SWAP_MOVES_LZ_SETTING'),
            ('the same key, sticky', st({'MODE': 'prod'}, {'MODE': 'stage'}, sticky=['MODE']), '', 'SEAM_OWNERSHIP_HELD'),
            ('a connection string differs', st(cs=({'Db': 'a'}, {'Db': 'b'})), '', 'SEAM_SWAP_MOVES_LZ_SETTING'),
            ('KIT_SETTING_KEYS names a sticky key', st({'feature_x': '1'}, {'feature_x': '1'}, sticky=['feature_x']),
             'feature_x', 'SEAM_SETTING_OWNERSHIP_CONFLICT'),
            ('equal non-sticky settings (control)', st({'MODE': 'same'}, {'MODE': 'same'}), '', 'SEAM_OWNERSHIP_HELD'),
            ('settings unreadable', dict(st(), fail=['webapp config appsettings']), '', 'SEAM_OWNERSHIP_NOT_ESTABLISHED')):
        seam, res, muts, calls = run_app(state, keys)
        out = (seam.get('outputs') or {}).get('seam_ownership')
        refused = want != 'SEAM_OWNERSHIP_HELD'
        # Only the calls made up to the seam step matter: a held seam lets the (fenced) job go on.
        upto = calls[:next((i for i, c in enumerate(calls) if c[0] == 'az' and any(w in c[1:5] for w in MUTATING)),
                           len(calls))]
        expect(out == want and (seam.get('outcome') == ('failure' if refused else 'success')) and
               (not muts if refused else True) and len(upto) >= 1,
               'S3 appservice: %s -> %s (%s, %s, %d mutation(s))' % (label, want, out, seam.get('outcome'), len(muts)))
        if label.startswith('a non-sticky'):
            expect('stage' not in str(seam) and 'prod\'' not in str(seam.get('outputs')),
                   'S3 appservice: the differing values are not shown')
            post = (res['steps'].get('posture') or {}).get('outputs') or {}
            expect(post.get('routing_result') == 'BLOCKED', 'S3 appservice: the posture routes the seam refusal BLOCKED (%s)'
                   % post.get('routing_result'))


def containerapp_cases():
    def st(env):
        s = W.containerapp_state()
        s['containerapp']['revisions']['web--r1']['env'] = env
        return s
    inputs = dict(github_environment='production', routing_result='PROCEED', environment_tier='dev',
                  resource_group='rg-a', containerapp_name='web', acr_login_server=W.REG, image_repository=W.REPO,
                  image_digest=W.NEW, cloud='commercial', rollback_on_failure=True, health_path='/health',
                  health_retries=1, health_interval_seconds=0)
    for label, env, keys, want in (
            ('KIT_SETTING_KEYS names a secret-backed key', {'DB_PASSWORD': {'secretRef': 'db'}}, 'DB_PASSWORD',
             'SEAM_SETTING_OWNERSHIP_CONFLICT'),
            ('a plain kit key (control)', {'feature_x': '1'}, 'feature_x', 'SEAM_OWNERSHIP_HELD')):
        res, final, calls = W.run_world(WFS['containerapp'], inputs, st(env),
                                        env_extra=dict(LEASE, KIT_SETTING_KEYS=keys))
        seam = res['steps'].get('seam') or {}
        out = (seam.get('outputs') or {}).get('seam_ownership')
        refused = want != 'SEAM_OWNERSHIP_HELD'
        expect(out == want and (not mutations(calls) if refused else True),
               'S4 containerapp: %s -> %s (%s, %d mutation(s))' % (label, want, out, len(mutations(calls))))


def lease_off():
    s = W.appservice_state()
    s['webapp']['slots']['production']['appsettings'] = {'MODE': 'prod'}
    s['webapp']['slots']['staging']['appsettings'] = {'MODE': 'stage'}
    seam, res, muts, calls = run_app(s, lease=False)
    expect(seam.get('outcome') == 'skipped' and res['evidence'].get('outcome.json', {}).get('deployment_outcome') ==
           'DEPLOY_HEALTHY', 'S5 the lease off: no seam step, the deploy is as before (%s, %s)'
           % (seam.get('outcome'), res['evidence'].get('outcome.json', {}).get('deployment_outcome')))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = W.D.bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    try:
        pure()
    except AttributeError as exc:
        expect(False, 'S1 deploy_contract.decide_seam exists (%s)' % exc)
    wiring()
    if not FAILS:
        appservice_cases()
        containerapp_cases()
    lease_off()
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: under the seam the deploy refuses, before its first mutation, a setting it does not own or '
          'one both sides claim (SEAM_SETTING_OWNERSHIP_CONFLICT) and a swap that would carry a non-sticky '
          'landing-zone setting (SEAM_SWAP_MOVES_LZ_SETTING); an unreadable setting is not established; values '
          'are never shown; without the seam nothing changes.')
    print('      STUBBED: tests/_fake_az.py models the settings reads; U4 (whether the image set writes DOCKER_* '
          'settings) is still a live question.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
