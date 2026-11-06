#!/usr/bin/env python3
"""The extended hand-off set the landing zone now vends is read by the deploy, recorded by name, and
documented; the app's own edge endpoint is purged after a verified release. (OF-5 K-7; KDEC-030 kit
items 5 and 8, decision D-4)

WHY THIS EXISTS

    The landing zone's hand-off write (its BUILD-12) now writes, beside the nine identifiers:
    KIT_RELEASE_BLOCK, KIT_ZONE_READINESS, KIT_EDGE_ENDPOINT (user-facing apps), KIT_SETTING_KEYS (empty
    by default), KIT_TARGET_LEASE_ACCOUNT (after G09) in each environment, and KIT_ACR_LOGIN_SERVER,
    KIT_IMAGE_REPOSITORY, KIT_PROMOTION_PREDECESSOR as repository variables; the deploy identity gets
    the lease container's data-plane role and the purge-only role at its own endpoint. The kit's
    contract named none of it, and KIT_EDGE_ENDPOINT had no consumer: D-4 (decided 2026-10-26) says the
    kit purges ONLY the app's own Front Door endpoint after a verified release, "not applicable"
    without one, never a pass.

CASES
    H1  the bind step records which of the extended set this environment vends -- names only, never a
        value (handoff_vended) -- identically in both deploy reusables; nothing vended -> empty
    H2  both reusables read every extended environment variable from vars in their job env
    H3  docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md documents every extended variable, where it lives
        (environment or repository), the lease data-plane role and the purge-only role
    P1  a healthy deploy with KIT_EDGE_ENDPOINT vended purges exactly that endpoint, once, after the
        provenance stamp: EDGE_PURGED
    P2  an unhealthy deploy purges nothing
    P3  no endpoint vended -> EDGE_PURGE_NOT_APPLICABLE, no call (recorded, never a pass)
    P4  a vended value that is not an afdEndpoints resource id -> EDGE_PURGE_REFUSED, no call
    P5  the purge fails -> EDGE_PURGE_FAILED; the release stays DEPLOY_HEALTHY and the posture routes
        PROCEED_WITH_ADVISORY (stale cache is owed, not a failed release)
    P6  parity (KDEC-030 D-4, integrate/r8): the Static Web Apps reusable carries the same bind (H1, H2)
        and the same purge step -- id purge, after the provenance stamp and before the lease end, only
        after a verified production, continue-on-error, the posture reading its outcome and the vended
        set; P1-P5 run against it in tests/prove_deploy_staticwebapp.py J12

EXIT 0 proven   1 a case failed   2 could not be checked
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402
import _step_harness as H  # noqa: E402

FAILS = []
EXTENDED = ('KIT_RELEASE_BLOCK', 'KIT_ZONE_READINESS', 'KIT_SETTING_KEYS', 'KIT_EDGE_ENDPOINT',
            'KIT_TARGET_LEASE_ACCOUNT')
REPO_VARS = ('KIT_ACR_LOGIN_SERVER', 'KIT_IMAGE_REPOSITORY', 'KIT_PROMOTION_PREDECESSOR')
EP = ('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-edge/providers/'
      'Microsoft.Cdn/profiles/afd-shared/afdEndpoints/ep-shop')
WFS = {'appservice': W.D.APPSERVICE, 'containerapp': W.D.CONTAINERAPP}
SWA = os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-staticwebapp.yml')
# The hand-off set and the purge are every deploy reusable's (D-4): the static checks cover all three.
ALL_WFS = dict(WFS, staticwebapp=SWA)


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def static(bash):
    bodies = set()
    for name, wf in sorted(ALL_WFS.items()):
        doc = W.D.load(wf)
        jenv = W.D.job(doc).get('env') or {}
        for v in EXTENDED:
            expect(str(jenv.get(v)) == '${{ vars.%s }}' % v, 'H2 %s: job env %s reads vars.%s' % (name, v, v))
        bind = H.step(os.path.relpath(wf, ROOT), 'deploy', 'bind')
        bodies.add((bind or {}).get('run'))
        for vended, want in (({'KIT_RELEASE_BLOCK': 'none', 'KIT_ZONE_READINESS': 'READY',
                               'KIT_EDGE_ENDPOINT': EP}, 'KIT_RELEASE_BLOCK,KIT_ZONE_READINESS,KIT_EDGE_ENDPOINT'),
                             ({}, '')):
            ws = os.path.join(TMP, '%s-%d' % (name, len(os.listdir(TMP))))
            os.makedirs(ws)
            ctx = {'inputs.environment_tier': 'dev', 'inputs.resource_group': 'rg-a'}
            for v in EXTENDED:
                ctx['vars.%s' % v] = vended.get(v, '')
            r = H.run(bash, bind, ctx, ws)
            got = r['outputs'].get('handoff_vended')
            expect(r['rc'] == 0 and got == want and EP not in r['log'] and EP not in r['summary'],
                   'H1 %s: vended %s -> handoff_vended %r (names only; got %r)' % (name, sorted(vended), want, got))
    expect(len(bodies) == 1, 'H1 the three reusables carry the same bind body')
    for name, wf in sorted(ALL_WFS.items()):
        steps = W.D.steps(W.D.load(wf))
        ids = [s.get('id') for s in steps]
        pr = steps[ids.index('purge')] if 'purge' in ids else {}
        expect(bool(pr) and ids.index('provenance') < ids.index('purge') < ids.index('lease_end') and
               pr.get('continue-on-error') is True and "steps.serving.outcome == 'success'" in str(pr.get('if')) and
               '" purge' in (pr.get('run') or ''),
               'P6 %s: a purge step after the provenance stamp and before the lease end, only after a verified '
               'production, continue-on-error' % name)
        post = next((x for x in steps if x.get('id') == 'posture'), {})
        penv = str(post.get('env'))
        expect('steps.purge.outputs.edge_purge' in penv and 'steps.bind.outputs.handoff_vended' in penv and
               'EDGE_PURGE_FAILED' in (post.get('run') or ''),
               'P6 %s: the posture reads the purge outcome and the vended set, and routes a failed purge' % name)
    doc = io.open(os.path.join(ROOT, 'docs', 'architecture', 'LZ_KIT_HANDOFF_CONTRACT.md'), encoding='utf-8').read()
    for v in EXTENDED + REPO_VARS:
        expect(('`%s`' % v) in doc, 'H3 the hand-off contract documents %s' % v)
    expect('Storage Blob Data Contributor' in doc and 'Microsoft.Cdn/profiles/afdendpoints/Purge/action' in doc,
           'H3 the contract names the lease data-plane role and the purge-only action')
    expect('repository variable' in doc.lower(), 'H3 the contract says which values are repository variables')


def purges(calls):
    return [c for c in calls if c[0] == 'az' and c[1:4] == ['afd', 'endpoint', 'purge']]


def deploy(name, state, endpoint, **extra_inputs):
    base = dict(github_environment='production', routing_result='PROCEED', environment_tier='dev',
                resource_group='rg-a', acr_login_server=W.REG, image_repository=W.REPO, image_digest=W.NEW,
                cloud='commercial', rollback_on_failure=True, health_path='/health', health_retries=1,
                health_interval_seconds=0, version_metadata='{"git_sha": "%s"}' % ('f' * 40))
    if name == 'appservice':
        base.update(webapp_name='web', slot='staging', swap_on_healthy=True)
    else:
        base.update(containerapp_name='web')
    base.update(extra_inputs)
    res, final, calls = W.run_world(WFS[name], base, state, env_extra={'KIT_EDGE_ENDPOINT': endpoint})
    return res, final, calls


def purge_cases():
    for name in sorted(WFS):
        state = W.appservice_state if name == 'appservice' else W.containerapp_state
        res, final, calls = deploy(name, state(), EP)
        p = purges(calls)
        st = res['steps'].get('purge') or {}
        order = [n for n, _o in res['order']]
        ok_order = ('Stamp provenance (after health and a live read)' in order and
                    any(n.startswith('Purge the app') for n in order) and
                    order.index('Stamp provenance (after health and a live read)') <
                    next(i for i, n in enumerate(order) if n.startswith('Purge the app')))
        expect(len(p) == 1 and 'ep-shop' in p[0] and 'afd-shared' in p[0] and 'rg-edge' in p[0] and
               (st.get('outputs') or {}).get('edge_purge') == 'EDGE_PURGED' and ok_order,
               'P1 %s: one purge of the vended endpoint, after the provenance stamp (%d call(s), %s)'
               % (name, len(p), (st.get('outputs') or {}).get('edge_purge')))
        bad = state(unhealthy_images=[W.ref(W.NEW)])
        res, final, calls = deploy(name, bad, EP)
        expect(not purges(calls), 'P2 %s: an unhealthy deploy purges nothing' % name)
        res, final, calls = deploy(name, state(), '')
        st = res['steps'].get('purge') or {}
        expect(not purges(calls) and (st.get('outputs') or {}).get('edge_purge') == 'EDGE_PURGE_NOT_APPLICABLE',
               'P3 %s: no endpoint vended -> EDGE_PURGE_NOT_APPLICABLE, no call (%s)'
               % (name, (st.get('outputs') or {}).get('edge_purge')))
        res, final, calls = deploy(name, state(), '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/other')
        st = res['steps'].get('purge') or {}
        expect(not purges(calls) and (st.get('outputs') or {}).get('edge_purge') == 'EDGE_PURGE_REFUSED',
               'P4 %s: a value that is not an afdEndpoints id -> EDGE_PURGE_REFUSED, no call (%s)'
               % (name, (st.get('outputs') or {}).get('edge_purge')))
        res, final, calls = deploy(name, state(fail=['afd endpoint purge']), EP)
        st = res['steps'].get('purge') or {}
        post = (res['steps'].get('posture') or {}).get('outputs') or {}
        outcome = (res['evidence'].get('outcome.json') or {}).get('deployment_outcome')
        expect((st.get('outputs') or {}).get('edge_purge') == 'EDGE_PURGE_FAILED' and outcome == 'DEPLOY_HEALTHY' and
               post.get('routing_result') == 'PROCEED_WITH_ADVISORY',
               'P5 %s: a failed purge -> EDGE_PURGE_FAILED, still DEPLOY_HEALTHY, routed PROCEED_WITH_ADVISORY (%s, %s, %s)'
               % (name, (st.get('outputs') or {}).get('edge_purge'), outcome, post.get('routing_result')))


TMP = None


def main():
    global TMP
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    import shutil
    import tempfile
    TMP = tempfile.mkdtemp(prefix='handoff-ext-')
    try:
        static(bash)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    purge_cases()
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: both deploy reusables read the extended hand-off set and record by name what the environment '
          'vends; the contract documents it with its roles; the app\'s own edge endpoint is purged once after a '
          'verified release, not applicable without one, refused when it is not an endpoint id, and a failed '
          'purge is an advisory, never a failed release.')
    print('      STUBBED: the purge is tests/_fake_az.py; the purge role and its status poll (KDEC-030 U8) are live questions.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
