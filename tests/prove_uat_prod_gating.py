#!/usr/bin/env python3
"""Never a uat or prod deployment without a human approval from outside the app team. (owner 2026-11-06; KDEC-042)

WHY THIS EXISTS
    The owner: uat and prod are consistent production environments and require a sign-off from someone in
    platform or security, EVEN IF someone pushes straight from a branch to main. dev and test stay ungated.
    A team of one or two is fine because the approvers come from the platform and security pools, outside
    the app team. scripts/environment_protection.py classes the environment and reads its rules back before
    any cloud login; tests/check_deploy_environment_declared.py holds every deploy job to `environment:`.

WHAT IT PROVES (stand-in GitHub API on 127.0.0.1)
    G1  classing: the strongest of bound tier, .kit/environments.json and the name; an explicit class never
        lowers a production name; an unclassed or empty name is UNCLASSED
    G2  the decision over the stand-in, in-process: positives P1-P6, negatives N1-N16 (below)
    G3  THE SHIPPED STEP of all three deploy reusables, under bash, over the same cases: exit 0 for the
        positives, 1 for the negatives, the named outcome emitted; the reads go to GITHUB_API_URL (the run's
        own host, KDEC-027), the class file is read at GITHUB_SHA, and no token goes to a non-https host
    G4  push to main: a caller that deploys to prod on `push` reaches the same job, `environment: prod`, as a
        dispatch; GitHub's own required-reviewer wait therefore applies; the step's decision does not read
        the trigger; the kit's templates deploy only dev and test on push; a caller that picks the
        environment by trigger is refused (E5); the static check's own mutants are caught
    G5  mutants: each check removed from environment_protection.py is caught by G2

    P1 prod protected by a pool team, self-review prevented, app team declared   -> VERIFIED
    P2 uat protected                                                              -> VERIFIED
    P3 dev, no environment at all                                                 -> ENVIRONMENT_PROTECTION_NOT_REQUIRED
    P4 test, no rules                                                             -> ENVIRONMENT_PROTECTION_NOT_REQUIRED
    P5 an unpatterned name classed test in .kit/environments.json                 -> ENVIRONMENT_PROTECTION_NOT_REQUIRED
    P6 app team membership unreadable (403): recorded NOT_ESTABLISHED, decided on the rules -> VERIFIED
    N1 prod absent  N2 no reviewer rule  N3 empty reviewers  N4 self-review allowed  N5 rules unreadable
    N6 class file unreadable  N7 the app team's own Team is the only reviewer  N8 every reviewer a declared
    member  N9 no reviewer in the pools  N10 unclassed name  N11 empty name  N12 `prod` classed dev still
    gated  N13 a production name with a dev tier still gated  N14 settings unreadable  N15 pools from the
    settings file  N16 the variable's pools win over the settings file  N17 uat unprotected

EXIT 0 proven   1 a rule failed   2 could not be checked (no bash, no PyYAML)
"""
import argparse
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)
DEPLOYS = ['.github/workflows/reusable-deploy-appservice.yml', '.github/workflows/reusable-deploy-containerapp.yml',
           '.github/workflows/reusable-deploy-staticwebapp.yml']
SHA = 'c0ffee' + '0' * 34
ENV = '/repos/o/r/environments/%s'
CLASSES = '/repos/o/r/contents/.kit/environments.json'
SETTINGS = '/repos/o/r/contents/.kit/settings.json'
MEMBERS = '/orgs/o/teams/app-team/members'
POOLS = json.dumps({'platform': ['@o/platform-team'], 'security': ['@o/security']})


def team(slug):
    return {'type': 'Team', 'reviewer': {'slug': slug, 'name': slug}}


def user(login):
    return {'type': 'User', 'reviewer': {'login': login}}


def envdoc(reviewers=None, prevent=True, rule=True):
    rules = [{'type': 'wait_timer', 'wait_timer': 0}]
    if rule:
        rules.append({'type': 'required_reviewers', 'prevent_self_review': prevent, 'reviewers': reviewers or []})
    return {'name': 'x', 'protection_rules': rules}


def C(cid, env, tier, routes, want, ok, pools='', app='', tc=None):
    return {'id': cid, 'env': env, 'tier': tier, 'routes': routes, 'want': want, 'ok': ok,
            'vars': {'KIT_APPROVER_POOLS': pools, 'KIT_APP_TEAM': app}, 'tc': tc}


GOOD = envdoc([team('security')])
CASES = [
    C('P1', 'prod', 'prod', {ENV % 'prod': (200, GOOD), SETTINGS: (200, {'app_team': {'team': '@o/app-team'}})},
      'ENVIRONMENT_PROTECTION_VERIFIED', True, pools=POOLS, tc='APP_TEAM_INDEPENDENT'),
    C('P2', 'uat', 'uat', {ENV % 'uat': (200, envdoc([team('platform-team')]))}, 'ENVIRONMENT_PROTECTION_VERIFIED', True,
      pools=POOLS),
    C('P3', 'dev', 'dev', {}, 'ENVIRONMENT_PROTECTION_NOT_REQUIRED', True),
    C('P4', 'test', 'test', {ENV % 'test': (200, envdoc(rule=False))}, 'ENVIRONMENT_PROTECTION_NOT_REQUIRED', True),
    C('P5', 'qa-east', 'test', {CLASSES: (200, {'environments': [{'name': 'qa-east', 'class': 'test'}]})},
      'ENVIRONMENT_PROTECTION_NOT_REQUIRED', True),
    C('P6', 'prod', 'prod', {ENV % 'prod': (200, envdoc([user('alice')])), MEMBERS: (403, {})},
      'ENVIRONMENT_PROTECTION_VERIFIED', True, app='app-team', tc='NOT_ESTABLISHED'),
    C('N1', 'prod', 'prod', {}, 'ENVIRONMENT_NOT_FOUND', False),
    C('N2', 'prod', 'prod', {ENV % 'prod': (200, envdoc(rule=False))}, 'ENVIRONMENT_REVIEWERS_ABSENT', False),
    C('N3', 'prod', 'prod', {ENV % 'prod': (200, envdoc([]))}, 'ENVIRONMENT_REVIEWERS_EMPTY', False),
    C('N4', 'prod', 'prod', {ENV % 'prod': (200, envdoc([team('security')], prevent=False))},
      'ENVIRONMENT_SELF_REVIEW_ALLOWED', False),
    C('N5', 'prod', 'prod', {ENV % 'prod': (500, {})}, 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED', False),
    C('N6', 'prod', 'prod', {ENV % 'prod': (200, GOOD), CLASSES: (500, {})}, 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED', False),
    C('N7', 'prod', 'prod', {ENV % 'prod': (200, envdoc([team('app-team')])),
                             SETTINGS: (200, {'app_team': {'team': 'app-team'}})}, 'ENVIRONMENT_APPROVERS_ALL_APP_TEAM', False),
    C('N8', 'prod', 'prod', {ENV % 'prod': (200, envdoc([user('alice'), user('bob')]))},
      'ENVIRONMENT_APPROVERS_ALL_APP_TEAM', False, app=json.dumps({'team': 'app-team', 'members': ['alice', 'bob']})),
    C('N9', 'prod', 'prod', {ENV % 'prod': (200, envdoc([team('marketing')]))}, 'ENVIRONMENT_APPROVER_POOL_MISSING', False,
      pools=POOLS),
    C('N10', 'qa-east', 'dev', {}, 'ENVIRONMENT_UNCLASSED', False),
    C('N11', '', 'dev', {}, 'ENVIRONMENT_UNCLASSED', False),
    C('N12', 'prod', 'dev', {CLASSES: (200, {'classes': {'prod': 'dev'}}), ENV % 'prod': (200, envdoc(rule=False))},
      'ENVIRONMENT_REVIEWERS_ABSENT', False),
    C('N13', 'production-eu', 'dev', {ENV % 'production-eu': (200, envdoc(rule=False))}, 'ENVIRONMENT_REVIEWERS_ABSENT', False),
    C('N14', 'prod', 'prod', {ENV % 'prod': (200, GOOD), SETTINGS: (500, {})}, 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED', False),
    C('N15', 'prod', 'prod', {ENV % 'prod': (200, envdoc([team('marketing')])),
                              SETTINGS: (200, {'approver_pools': {'platform': ['platform-team'], 'security': ['security']}})},
      'ENVIRONMENT_APPROVER_POOL_MISSING', False),
    C('N16', 'prod', 'prod', {ENV % 'prod': (200, envdoc([team('marketing')])),
                              SETTINGS: (200, {'approver_pools': {'platform': ['marketing']}})},
      'ENVIRONMENT_APPROVER_POOL_MISSING', False, pools=json.dumps({'security': ['security']})),
    C('N17', 'uat', 'uat', {ENV % 'uat': (200, envdoc(rule=False))}, 'ENVIRONMENT_REVIEWERS_ABSENT', False),
]


def run_decide(ep, api, case):
    api.reset(case['routes'])
    a = argparse.Namespace(tier=case['tier'], environment=case['env'], repository='o/r', demand_json='', ref=SHA,
                           api_url=api.url)
    env = dict(case['vars'], GH_TOKEN='')
    outcome, _why, refused, _cls, _src, tc, _d = ep.decide(a, env)
    return outcome, refused, tc


def g1_classing(ep, check):
    for name, tier, spec, want in [('prod', 'dev', None, 'prod'), ('uat', 'dev', None, 'uat'), ('staging', 'dev', None, 'uat'),
                                   ('dev', 'dev', None, 'dev'), ('feature-test', 'dev', None, 'test'),
                                   ('qa', 'test', {'classes': {'qa': 'uat'}}, 'uat'),
                                   ('prod', 'dev', {'classes': {'prod': 'dev'}}, 'prod'),
                                   ('dev', 'prod', None, 'prod')]:
        got = ep.classify(name, tier, spec)[0]
        check(got == want, 'G1 %r at tier %s with %r classed %s, expected %s' % (name, tier, spec, got, want))
    for name, spec in [('qa-east', None), ('', None), ('build', {'environments': [{'name': 'build', 'tier': None}]})]:
        got = ep.classify(name, 'dev', spec)[2]
        check(got == ep.UNCLASSED, 'G1 %r was not UNCLASSED (%s)' % (name, got))
    check(ep.classify('qa', 'dev', {'classes': {'qa': 'staging'}})[2] == ep.NOT_ESTABLISHED,
          'G1 an unregistered explicit class was not NOT_ESTABLISHED')


def g2_decide(ep, api, check, quiet=False):
    for case in CASES:
        outcome, refused, tc = run_decide(ep, api, case)
        if not quiet:
            print('  G2 %-4s %-14s %-5s %-40s refused=%s app_team=%s' % (case['id'], case['env'] or "''", case['tier'],
                                                                         outcome, refused, tc))
        check(outcome == case['want'], 'G2 %s: %s, expected %s' % (case['id'], outcome, case['want']))
        check(refused == (not case['ok']), 'G2 %s: refused=%s, expected %s' % (case['id'], refused, not case['ok']))
        if case['tc']:
            check(tc == case['tc'], 'G2 %s: app_team_check %s, expected %s' % (case['id'], tc, case['tc']))


def g3_steps(api, check, bash, yaml):
    work = tempfile.mkdtemp(prefix='gating-')
    try:
        kit = os.path.join(work, 'rt', 'kit-deploy')
        os.makedirs(kit)
        shutil.copyfile(os.path.join(ROOT, 'scripts', 'environment_protection.py'), os.path.join(kit, 'environment_protection.py'))
        for wf in DEPLOYS:
            doc = yaml.safe_load(io.open(os.path.join(ROOT, wf), encoding='utf-8'))
            job = doc['jobs']['deploy']
            step = [s for s in job['steps'] if s.get('id') == 'protection'][0]
            check(job['env'].get('DEPLOY_ENVIRONMENT') == '${{ inputs.github_environment }}',
                  'G3 %s: the step reads a different environment from the one the job runs in' % wf)
            check(step['env'].get('KIT_APPROVER_POOLS') == '${{ vars.KIT_APPROVER_POOLS }}' and
                  step['env'].get('KIT_APP_TEAM') == '${{ vars.KIT_APP_TEAM }}', 'G3 %s: pools/app team not passed' % wf)
            check('api.github.com' not in step['run'] and '--ref "${GITHUB_SHA:-}"' in step['run'],
                  'G3 %s: the step names a fixed API host or no ref' % wf)
            script = os.path.join(work, 'step.sh')
            io.open(script, 'w', encoding='utf-8', newline='\n').write(step['run'])
            for case in CASES:
                api.reset(case['routes'])
                outf = os.path.join(work, 'out')
                io.open(outf, 'w').close()
                summ = os.path.join(work, 'summ')
                io.open(summ, 'w').close()
                env = dict(os.environ, RUNNER_TEMP=os.path.join(work, 'rt'), GITHUB_OUTPUT=outf, GITHUB_STEP_SUMMARY=summ,
                           GITHUB_REPOSITORY='o/r', GITHUB_API_URL=api.url, GITHUB_SHA=SHA,
                           DEPLOY_ENVIRONMENT=case['env'],
                           ENVIRONMENT_TIER=case['tier'],
                           DEPLOY_APPROVAL='',
                           GH_TOKEN='a-token-that-must-not-leave-https', **case['vars'])
                p = subprocess.run([bash, script], capture_output=True, text=True, env=env)
                emitted = dict(l.rstrip('\n').split('=', 1) for l in io.open(outf, encoding='utf-8') if '=' in l)
                got = emitted.get('environment_protection')
                check((p.returncode == 0) == case['ok'] and got == case['want'],
                      'G3 %s %s: exit %d outcome %s, expected %s %s\n%s' % (os.path.basename(wf), case['id'], p.returncode,
                                                                          got, 'proceed' if case['ok'] else 'refusal',
                                                                          case['want'], (p.stdout + p.stderr)[-300:]))
                check(not any('Authorization' in r['headers'] for r in api.requests),
                      'G3 %s %s: a token was sent to a non-https host' % (wf, case['id']))
                if case['id'] == 'P1':
                    reads = dict((r['path'], r['query']) for r in api.requests)
                    check(reads.get(CLASSES, {}).get('ref') == [SHA], 'G3 %s P1: the class file was not read at GITHUB_SHA' % wf)
                    check(ENV % 'prod' in reads, 'G3 %s P1: the environment was not read on GITHUB_API_URL' % wf)
            print('  G3 %-46s %d cases as shipped' % (os.path.basename(wf), len(CASES)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def g4_push(ep, api, check, yaml):
    import check_deploy_environment_declared as ced
    check(not ced.problems(ROOT), 'G4 the kit tree fails the environment-declared check: %r' % ced.problems(ROOT))
    check(ced.self_test() == 0, 'G4 the environment-declared check missed one of its mutants')
    src = io.open(os.path.join(ROOT, 'scripts', 'environment_protection.py'), encoding='utf-8').read()
    check('GITHUB_EVENT_NAME' not in src and 'event_name' not in src, 'G4 the decision reads the trigger')
    for wf in DEPLOYS + ['.github/workflows/reusable-rollback-sequence.yml']:
        doc = yaml.safe_load(io.open(os.path.join(ROOT, wf), encoding='utf-8'))
        for jn, job in doc['jobs'].items():
            expr = str(job.get('environment') or '')
            if not expr:
                continue
            for event in ('push', 'workflow_dispatch'):
                resolved = expr.replace('${{ inputs.github_environment }}', 'prod')
                check(resolved == 'prod', 'G4 %s %s on %s runs in %r, not the caller\'s prod' % (wf, jn, event, resolved))
    # GitHub holds a job in `environment: prod` until a required reviewer approves (its documented behaviour);
    # a push-triggered caller reaches the same job, so it waits on the same reviewers the step verified.
    api.reset({ENV % 'prod': (200, GOOD)})
    a = argparse.Namespace(tier='prod', environment='prod', repository='o/r', demand_json='', ref=SHA, api_url=api.url)
    on_push = ep.decide(a, {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main'})[0]
    on_dispatch = ep.decide(a, {'GITHUB_EVENT_NAME': 'workflow_dispatch'})[0]
    waits = any(r.get('type') == 'required_reviewers' and r.get('reviewers') for r in GOOD['protection_rules'])
    check(on_push == on_dispatch == ep.VERIFIED and waits, 'G4 a push to main decided %s, a dispatch %s' % (on_push, on_dispatch))
    api.reset({ENV % 'prod': (200, envdoc(rule=False))})
    check(ep.decide(a, {'GITHUB_EVENT_NAME': 'push'})[2] is True, 'G4 a push to main deployed to an unprotected prod')
    # the kit's own templates: on push they deploy only dev and test (literal); uat/prod only through a dispatch
    for t in ('templates/build-deploy.yml', 'templates/build-deploy-static.yml'):
        doc = yaml.safe_load(io.open(os.path.join(ROOT, t), encoding='utf-8'))
        for jn, job in doc['jobs'].items():
            if not str(job.get('uses') or '').split('@')[0].endswith(tuple(ced.DEPLOY_REUSABLES)):
                continue
            cond = str(job.get('if') or '')
            ge = str((job.get('with') or {}).get('github_environment') or '')
            if "github.event_name == 'push'" in cond:
                check(ep.name_class(ge) in ('dev', 'test'), 'G4 %s %s deploys %r on push' % (t, jn, ge))
    work = tempfile.mkdtemp(prefix='gating-push-')
    try:
        for d in ('.github/workflows', 'templates'):
            shutil.copytree(os.path.join(ROOT, d), os.path.join(work, d))
        caller = ('on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    uses: o/kit/.github/workflows/'
                  'reusable-deploy-containerapp.yml@%s\n    with:\n      github_environment: %s\n')
        p = os.path.join(work, 'templates', 'push-to-prod.yml')
        io.open(p, 'w', encoding='utf-8', newline='\n').write(caller % (SHA, 'prod'))
        check(not ced.problems(work), 'G4 a plain push-to-prod caller was refused: %r' % ced.problems(work))
        io.open(p, 'w', encoding='utf-8', newline='\n').write(
            caller % (SHA, "${{ github.event_name == 'push' && 'dev' || 'prod' }}"))
        check(any(x.startswith('E5') for x in ced.problems(work)), 'G4 a caller picking the environment by trigger passed')
    finally:
        shutil.rmtree(work, ignore_errors=True)


MUTANTS = [
    ('not_found', '    if env_doc == 404:\n', '    if False:\n'),
    ('reviewers_absent', '    if not rv:\n', '    if False:\n'),
    ('reviewers_empty', '    if not reviewers:\n', '    if False:\n'),
    ('self_review', "and not all(r.get('prevent_self_review') is True for r in rv):", 'and False:'),
    ('pool', '    if pools is not None and not any(', '    if False and not any('),
    ('all_app_team', "    if tc == 'APP_TEAM_ONLY':", '    if False:'),
    ('unclassed', '(exp is None and pat is None)', 'False'),
    ('unreadable_rules', "list):\n        return NOT_ESTABLISHED", 'list):\n        return VERIFIED'),
    ('explicit_lowers', '    cls, src = max(cands, key=lambda cs: RANK[cs[0]])',
     "    cls, src = (exp, 'x') if exp else max(cands, key=lambda cs: RANK[cs[0]])"),
    ('class_file_unreadable', '    if spec_err:\n', '    if False:\n'),
    ('settings_unreadable', '        if serr or not', '        if False and not'),
    ('variable_wins', "    pools, team = parse_pools(environ.get('KIT_APPROVER_POOLS')), parse_team(environ.get('KIT_APP_TEAM'))",
     "    pools, team = None, None"),
    ('uat_gated', "cls in PRODUCTION_TIERS, cls, src, tc, demand", "cls == 'prod', cls, src, tc, demand"),
]


def g5_mutants(api, check):
    src = io.open(os.path.join(ROOT, 'scripts', 'environment_protection.py'), encoding='utf-8').read()
    work = tempfile.mkdtemp(prefix='gating-mut-')
    try:
        for name, old, new in MUTANTS:
            if old not in src:
                check(False, 'G5 mutant %s: its target text is not in the script' % name)
                continue
            p = os.path.join(work, 'ep_%s.py' % name.lower())
            io.open(p, 'w', encoding='utf-8', newline='\n').write(src.replace(old, new, 1))
            spec = importlib.util.spec_from_file_location('ep_%s' % name.lower(), p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            fails = []
            g1_classing(mod, lambda c, m: fails.append(m) if not c else None)
            g2_decide(mod, api, lambda c, m: fails.append(m) if not c else None, quiet=True)
            print('  G5 mutant %-22s %s' % (name, 'caught (%s)' % fails[0][:60] if fails else 'MISSED'))
            check(fails, 'G5 mutant %s was not caught' % name)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    try:
        import yaml
        import environment_protection as ep
        import prove_bootstrap_failure as pbf
        import _env_api_standin as standin
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bad = []

    def check(c, m):
        if not c:
            bad.append(m)

    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    with standin.StandIn() as api:
        g1_classing(ep, check)
        g2_decide(ep, api, check)
        g3_steps(api, check, bash, yaml)
        g4_push(ep, api, check, yaml)
        g5_mutants(api, check)
    for b in bad:
        print('FAIL: ' + b)
    if bad:
        return 1
    print('PASS: uat and prod are refused before login unless the environment exists, names reviewers, prevents '
          'self-review, includes a platform or security pool member and is not the app team alone; dev and test '
          'pass ungated; an unclassed or empty name is refused; a push to main waits on the same environment; '
          'every check removed is caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
