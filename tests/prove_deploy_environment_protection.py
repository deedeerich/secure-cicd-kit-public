#!/usr/bin/env python3
"""A uat or prod deploy refuses, before login, when the GitHub environment it runs in lacks the
reviewers the policy demands. (owner, 2026-10-22; KDEC-014's environment-reviewer half)

WHY THIS EXISTS

    For a single-developer product, uat and prod need ONE approver from a named reviewer group
    (architect / security / platform) who is NOT the deploying developer: required reviewers with
    self-review prevented on the GitHub environment. The kit cannot set that; it can read it back.
    Until now the reviewer half was "a platform setting the kit cannot set or read", so a deploy to
    an unprotected prod environment went ahead. This proves:

      1  scripts/environment_protection.py classifies the environment API answer by name:
         every environment_protection value (assurance-taxonomy.yaml) -- and a passed demand can
         only tighten the kit default, never weaken it.
      2  BOTH deploy reusables declare `deploy_approval`, inline the script, and run a `protection`
         step AFTER the tier is bound and BEFORE the verdict and any login.
      3  THE STEP, AS SHIPPED, run against a recorded API answer: prod unprotected -> refused (exit
         1); prod with self-review allowed -> refused; prod protected -> proceeds; prod unreadable ->
         refused (not established is not a pass); dev unprotected -> proceeds with a warning.

EXIT 0 proven   1 a rule failed   2 could not be checked
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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)
DEPLOYS = ['.github/workflows/reusable-deploy-appservice.yml', '.github/workflows/reusable-deploy-containerapp.yml']


def team(slug):
    return {'type': 'Team', 'reviewer': {'slug': slug, 'name': slug.title()}}


def rule(reviewers, prevent=True):
    return {'protection_rules': [{'type': 'wait_timer', 'wait_timer': 0},
                                 {'type': 'required_reviewers', 'prevent_self_review': prevent,
                                  'reviewers': reviewers}]}


def main():
    try:
        import yaml
        import environment_protection as ep
        import prove_bootstrap_failure as pbf
    except ImportError as exc:
        print('FAIL: %s' % exc)
        return 1
    bad = []

    def check(c, m):
        if not c:
            bad.append(m)

    # 1  classification
    groups = json.dumps({'prod': {'approver_groups': ['architects', 'security', 'platform']}})
    cases = [
        ('prod', '', rule([team('security')]), 'ENVIRONMENT_PROTECTION_VERIFIED'),
        ('prod', '', {'protection_rules': []}, 'ENVIRONMENT_REVIEWERS_ABSENT'),
        ('prod', '', rule([]), 'ENVIRONMENT_REVIEWERS_ABSENT'),
        ('prod', '', rule([team('security')], prevent=False), 'ENVIRONMENT_SELF_REVIEW_ALLOWED'),
        ('prod', '', None, 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED'),
        ('prod', '', {'name': 'prod'}, 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED'),
        ('prod', groups, rule([team('platform')]), 'ENVIRONMENT_PROTECTION_VERIFIED'),
        ('prod', groups, rule([team('platform'), {'type': 'User', 'reviewer': {'login': 'dev1'}}]), 'ENVIRONMENT_APPROVER_GROUP_MISSING'),
        ('prod', groups, rule([team('marketing')]), 'ENVIRONMENT_APPROVER_GROUP_MISSING'),
        ('uat', '', rule([team('security')]), 'ENVIRONMENT_PROTECTION_VERIFIED'),
        ('dev', '', {'protection_rules': []}, 'ENVIRONMENT_PROTECTION_NOT_REQUIRED'),
        ('prod', '{not json', rule([team('security')]), 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED'),
    ]
    for tier, demand, doc, want in cases:
        d, _note = ep.demand_for(tier, demand)
        got = ep.evaluate(doc, d)[0]
        check(got == want, 'rule 1: tier %s demand %r -> %s, expected %s' % (tier, demand[:40], got, want))
    weak = json.dumps({'prod': {'approvers_required': 0, 'self_review_prevented': 'not_required'}})
    d, _n = ep.demand_for('prod', weak)
    check(d['approvers_required'] == 1 and d['self_review_prevented'] == 'required',
          'rule 1: a passed deploy_approval weakened the prod default: %r' % d)
    d, _n = ep.demand_for('dev', json.dumps({'dev': {'approver_groups': ['security']}}))
    check(d['approvers_required'] == 1, 'rule 1: named groups at dev did not demand an approver: %r' % d)

    # 2  wiring
    bodies = {}
    for wf in DEPLOYS:
        doc = yaml.safe_load(io.open(os.path.join(ROOT, wf), encoding='utf-8'))
        on = doc.get('on', doc.get(True)) or {}
        check('deploy_approval' in ((on.get('workflow_call') or {}).get('inputs') or {}),
              'rule 2: %s does not declare deploy_approval' % wf)
        steps = doc['jobs']['deploy']['steps']
        ids = [s.get('id') for s in steps]
        names = [s.get('name', '') for s in steps]
        check('protection' in ids, 'rule 2: %s has no protection step' % wf)
        if 'protection' not in ids:
            continue
        i = ids.index('protection')
        login = next((n for n, s in enumerate(names) if s.startswith('Azure login')), len(steps))
        check('bind' in ids and ids.index('bind') < i < ids.index('verdict') < login,
              'rule 2: %s runs protection outside bind < protection < verdict < login' % wf)
        mat = next((s for s in steps if s.get('name') == 'Materialise the deploy contract scripts'), {})
        check('environment_protection.py' in (mat.get('run') or ''),
              'rule 2: %s does not materialise environment_protection.py' % wf)
        bodies[wf] = steps[i]
        out = (doc['jobs']['deploy'].get('outputs') or {})
        check('environment_protection' in out, 'rule 2: %s does not expose environment_protection' % wf)

    # 3  the step as shipped
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    work = tempfile.mkdtemp(prefix='env-protect-')
    try:
        kit = os.path.join(work, 'rt', 'kit-deploy')
        os.makedirs(kit)
        shutil.copyfile(os.path.join(ROOT, 'scripts', 'environment_protection.py'),
                        os.path.join(kit, 'environment_protection.py'))
        api = os.path.join(work, 'api')

        def answer(name, doc):
            d = os.path.join(api, 'repos', 'o', 'r', 'environments')
            if not os.path.isdir(d):
                os.makedirs(d)
            p = os.path.join(d, name)
            if doc is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                io.open(p, 'w', encoding='utf-8').write(json.dumps(doc))

        runs = [('prod-unprotected', 'prod', {'protection_rules': []}, False),
                ('prod-self-review', 'prod', rule([team('security')], prevent=False), False),
                ('prod-protected', 'prod', rule([team('security')]), True),
                ('prod-unreadable', 'prod', None, False),
                ('dev-unprotected', 'dev', {'protection_rules': []}, True)]
        for wf, step in sorted(bodies.items()):
            for name, tier, doc, ok in runs:
                answer('production', doc)
                outf = os.path.join(work, 'out')
                io.open(outf, 'w').close()
                summ = os.path.join(work, 'summ')
                io.open(summ, 'w').close()
                script = os.path.join(work, 'step.sh')
                io.open(script, 'w', encoding='utf-8', newline='\n').write(step.get('run') or '')
                api_url = 'file:///' + api.replace('\\', '/').lstrip('/')
                env = dict(
                    os.environ,
                    RUNNER_TEMP=os.path.join(work, 'rt'),
                    GITHUB_OUTPUT=outf,
                    GITHUB_STEP_SUMMARY=summ,
                    GITHUB_REPOSITORY='o/r',
                    GITHUB_API_URL=api_url,
                    DEPLOY_ENVIRONMENT='production',
                    ENVIRONMENT_TIER=tier,
                    DEPLOY_APPROVAL='',
                    GH_TOKEN='')
                p = subprocess.run([bash, script], capture_output=True, text=True, env=env)
                emitted = dict(l.rstrip('\n').split('=', 1) for l in io.open(outf, encoding='utf-8') if '=' in l)
                print('  %-46s %-18s exit=%d %s' % (os.path.basename(wf), name, p.returncode,
                                                    emitted.get('environment_protection')))
                check((p.returncode == 0) == ok, 'rule 3: %s %s exit %d, expected %s\n%s'
                      % (wf, name, p.returncode, 'proceed' if ok else 'refusal', (p.stdout + p.stderr)[-400:]))
                check(emitted.get('environment_protection'), 'rule 3: %s %s emitted no outcome' % (wf, name))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: ' + b)
        return 1
    print('PASS: the environment\'s protection rules are read back and classified by name; a passed demand '
          'only tightens; both deploys check them after binding the tier and before the verdict and login; '
          'an unprotected, self-reviewable or unreadable prod environment is refused, dev proceeds.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
