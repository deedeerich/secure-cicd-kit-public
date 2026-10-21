#!/usr/bin/env python3
"""A deploy runs under the tier, and against the target, its GitHub environment vends -- or refuses.

WHY THIS EXISTS (ledger P-01, LZ-1, section 5 B-13; docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md)

    The landing zone writes, per application and environment, KIT_ENVIRONMENT_TIER, the target
    (KIT_RESOURCE_GROUP, KIT_APP_NAME, KIT_ACR_LOGIN_SERVER, KIT_IMAGE_REPOSITORY, KIT_CLOUD) and the
    AZURE_* identifiers into the application repository's GitHub ENVIRONMENT, as variables. A job
    that CALLS a reusable workflow cannot declare `environment:`, so none of those values is
    readable where the caller writes `with:`. The deploy reusables took `environment_tier` as a
    caller string -- the starter template typed `prod` for every target -- and logged in with
    `secrets.AZURE_*` only, so a vended VARIABLE identity was never read. The tier decides the
    production rules (no irreversible deploy at uat/prod; KDEC-014's version-gap refusal), so a tier
    the caller types is a control the caller sets.

WHAT IS BUILT
    The deploy job runs IN the environment, so it reads the vended values itself (job env
    KIT_BOUND_*) and a step BEFORE the gate verdict -- `Bind the tier and target to the GitHub
    environment (refuse before login)` -- binds each one: an empty input is filled from the
    environment (GITHUB_ENV), an input that disagrees with it is refused before login, a vended value
    that is not a plain name is refused without being echoed, and an environment that vends nothing
    leaves the inputs as given (UNBOUND, recorded). Azure login reads `secrets.X || vars.X`.

WHAT IS RUN
    The bind step of both reusables AS SHIPPED (steps compared byte for byte, so they cannot drift),
    under GitHub's shell, with job env resolved from stubbed `vars.*` and `inputs.*`. Then the
    bound tier is handed to the shipped `Gate verdict (refuse before login)` step the way the runner
    hands a GITHUB_ENV value to every later step, and the posture step routes a bind refusal.

CASES (docs/PROOF_RULE.md)
    allowed           tier '' + vended prod -> bound to prod; matching input -> BOUND, no rewrite
    attack            input dev vs vended prod; another resource group; a vended value carrying a
                      workflow command; a vended gov cloud under a commercial login -> refused, exit 1
    missing-evidence  nothing vended -> UNBOUND, inputs as given (a pipeline outside the landing zone)
    recovery          the bound tier reaches the verdict step: prod + an established VERSION_GAP with
                      no exception is refused; the same advisory at a vended test tier proceeds
    posture           a bind refusal routes BLOCKED

    The platform behaviour this rests on -- an environment's variables visible to a reusable
    workflow's job that declares that environment, and a GITHUB_ENV value overriding job-level env
    for later steps -- is INFERRED from the platform documentation; the live dispatch is owed.

EXIT 0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

BIND = 'Bind the tier and target to the GitHub environment (refuse before login)'
VERDICT = 'Gate verdict (refuse before login)'
POSTURE = 'posture'
# The job variable the tier travels in. A setting's name, not vocabulary (hence the spelling).
TIER_VAR = 'environment_tier'.upper()
WFS = {'appservice': ('.github/workflows/reusable-deploy-appservice.yml', 'webapp_name'),
       'containerapp': ('.github/workflows/reusable-deploy-containerapp.yml', 'containerapp_name')}
VENDED = ('environment_tier', 'resource_group', 'app_name', 'acr_login_server', 'image_repository',
          'cloud')


def ctx(app_input, inputs, vended):
    c = {}
    for k, v in inputs.items():
        c['inputs.%s' % (app_input if k == 'app_name' else k)] = v
    for k, v in vended.items():
        c['vars.KIT_%s' % k.upper()] = v
    return c


BASE = {'environment_tier': '', 'resource_group': 'rg-a', 'app_name': 'web',
        'acr_login_server': 'registry.example', 'image_repository': 'shop/web',
        'cloud': 'commercial', 'routing_result': 'PROCEED'}


def static(bad):
    bodies = {}
    for name, (wf, app_input) in WFS.items():
        doc = H.load(wf)
        steps = doc['jobs']['deploy']['steps']
        names = [s.get('name') for s in steps]
        if BIND not in names:
            bad.append('%s: no step %r -- the tier and target are whatever the caller typed'
                       % (name, BIND))
            continue
        bi = names.index(BIND)
        gi = names.index(VERDICT) if VERDICT in names else -1
        li = [i for i, s in enumerate(steps) if 'azure/login' in str(s.get('uses', ''))]
        if gi < bi or not li or li[0] < bi:
            bad.append('%s: the bind step must precede the gate verdict and azure/login' % name)
        jenv = doc['jobs']['deploy'].get('env') or {}
        for k in VENDED:
            want = '${{ vars.KIT_%s }}' % k.upper()
            if str(jenv.get('KIT_BOUND_%s' % k.upper())) != want:
                bad.append('%s: job env KIT_BOUND_%s is not %s' % (name, k.upper(), want))
        login = steps[li[0]] if li else {}
        for s in ('AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID'):
            vals = ' '.join(str(v) for v in (login.get('with') or {}).values())
            if 'vars.%s' % s not in vals:
                bad.append('%s: azure/login never reads vars.%s -- the contract vends the '
                           'identity as a variable' % (name, s))
        bodies[name] = steps[bi].get('run')
        post = [s for s in steps if s.get('id') == POSTURE]
        if not post or 'steps.bind.outcome' not in str(post[0].get('env')):
            bad.append('%s: the posture step does not read the bind step outcome' % name)
    if len(set(bodies.values())) > 1:
        bad.append('the two reusables carry DIFFERENT bind step bodies; one would drift')
    return len(bodies) == 2


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    bad = []
    if not static(bad):
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    tmp = tempfile.mkdtemp(prefix='deploy-binding-probe-')
    try:
        for name, (wf, app_input) in WFS.items():
            bind = H.step(wf, 'deploy', BIND)
            verdict = H.step(wf, 'deploy', VERDICT)
            posture = H.step(wf, 'deploy', POSTURE)
            n = [0]

            def run(step, c, extra=None):
                n[0] += 1
                ws = os.path.join(tmp, '%s-%d' % (name, n[0]))
                os.makedirs(ws)
                return H.run(bash, step, c, ws, None, extra)

            # (case, input overrides, vended, must_pass, binding, env writes expected)
            cases = [
                ('allowed-fill', {}, {'environment_tier': 'prod', 'resource_group': 'rg-a'}, True,
                 'BOUND', {TIER_VAR: 'prod'}),
                ('allowed-match', {'environment_tier': 'prod'}, {'environment_tier': 'prod'}, True,
                 'BOUND', {}),
                ('attack-tier', {'environment_tier': 'dev'}, {'environment_tier': 'prod'}, False,
                 'REFUSED', {}),
                ('attack-target', {}, {'environment_tier': 'test', 'resource_group': 'rg-other'},
                 False, 'REFUSED', {}),
                ('attack-app', {}, {'app_name': 'someone-else'}, False, 'REFUSED', {}),
                ('attack-command', {}, {'environment_tier': 'prod\n::warning::x'}, False,
                 'REFUSED', {}),
                ('attack-cloud', {'cloud': 'commercial'}, {'cloud': 'gov'}, False, 'REFUSED', {}),
                ('missing-unbound', {'environment_tier': 'dev'}, {}, True, 'UNBOUND', {}),
            ]
            for case, over, vended, must, binding, writes in cases:
                inputs = dict(BASE, **over)
                r = run(bind, ctx(app_input, inputs, vended))
                o, e = r['outputs'], r['env']
                print('  %-13s %-15s exit=%d target_binding=%-8s env=%s'
                      % (name, case, r['rc'], o.get('target_binding'), e))
                if (r['rc'] == 0) != must:
                    bad.append('%s %s: exit %d, want %s\n%s'
                               % (name, case, r['rc'], 'pass' if must else 'refusal',
                                  r['log'][-400:]))
                if o.get('target_binding') != binding:
                    bad.append('%s %s: target_binding=%r, want %s'
                               % (name, case, o.get('target_binding'), binding))
                for k, v in writes.items():
                    if e.get(k) != v:
                        bad.append('%s %s: GITHUB_ENV %s=%r, want %r -- the empty input was not '
                                   'filled from the environment' % (name, case, k, e.get(k), v))
                if not writes and e:
                    bad.append('%s %s: wrote %r to GITHUB_ENV; only an EMPTY input is filled'
                               % (name, case, e))
                if case == 'attack-command' and '::warning::x' in r['log']:
                    bad.append('%s %s: the vended value reached the log as a workflow command'
                               % (name, case))

            # recovery: the bound tier reaches the KDEC-014 decision, as GITHUB_ENV reaches every
            # later step on the runner (it overrides the job-level tier variable).
            for tier, must in (('prod', False), ('test', True)):
                r = run(bind, ctx(app_input, BASE, {'environment_tier': tier}))
                c = ctx(app_input, dict(BASE, routing_result='PROCEED_WITH_ADVISORY',
                                        advisory_causes='VERSION_GAP'), {})
                v = run(verdict, c, {TIER_VAR: r['env'].get(TIER_VAR, '')})
                print('  %-13s %-15s bound %-5s -> verdict exit=%d ruling=%s'
                      % (name, 'recovery', tier, v['rc'], v['outputs'].get('version_gap_ruling')))
                if (v['rc'] == 0) != must:
                    bad.append('%s recovery: a VERSION_GAP at a vended %s tier %s (exit %d)'
                               % (name, tier, 'was refused' if must else 'proceeded', v['rc']))

            # posture: a bind refusal is an observed refusal before the point of no return.
            pc = {'inputs.routing_result': 'PROCEED', 'steps.bind.outcome': 'failure',
                  'job.status': 'failure', 'steps.report.outcome': 'failure',
                  'steps.report.outputs.deployment_outcome': 'DEPLOY_REFUSED',
                  'inputs.rollback_on_failure': 'true', 'inputs.slot': 'staging',
                  'inputs.swap_on_healthy': 'true', 'inputs.health_path': '/health',
                  'inputs.health_retries': '1', 'inputs.health_interval_seconds': '1'}
            p = run(posture, pc)
            print('  %-13s %-15s routing_result=%s' % (name, 'posture', p['outputs'].get(
                'routing_result')))
            if p['outputs'].get('routing_result') != 'BLOCKED':
                bad.append('%s posture: a bind refusal routed %r, want BLOCKED'
                           % (name, p['outputs'].get('routing_result')))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: both deploy reusables bind the tier and the target to their GitHub environment '
          'before the verdict and before login: an empty input is filled from the vended value, a '
          'disagreeing one is refused, a vended value that is not a plain name is refused unechoed, '
          'and nothing vended leaves the inputs as given (UNBOUND). Login reads the vended '
          'variables when no secret exists.')
    print('      STUBBED. That a reusable job sees its environment\'s variables, and that GITHUB_ENV '
          'overrides job env, is INFERRED from the platform documentation: live dispatch owed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
