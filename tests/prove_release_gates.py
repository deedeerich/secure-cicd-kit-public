#!/usr/bin/env python3
"""A release stops, before login, when the landing zone has stopped the platform, when the zone is not
ready for uat/prod, or when the approval is the requester's or the author's own, or not bound to the
digest being released. (OF-5, the LZ-vs-kit deployment review, K-1 K-2 K-3; KDEC-034 PROPOSED)

WHY THIS EXISTS

    The landing zone's design was stronger on three release preconditions the kit did not hold:
      K-3  its halt and its apply_block (TTL, budget cap) stopped LZ applies but never a release;
      K-2  its readiness gates decided whether the ZONE may take uat/prod, and no release read them;
      K-1  its owner confirms the exact plan digest and approver != confirmer != requester, while a
           GitHub environment's self-review prevention excludes only the run's trigger.
    The vend now writes KIT_RELEASE_BLOCK and KIT_ZONE_READINESS into every kit environment; the kit
    refuses on them, and reads the run's own approvals, in scripts/release_gates.py.

WHAT IS PROVEN

    1  release_gates.py decides by name: every release_block, zone_readiness_gate and release_approval
       value (assurance-taxonomy.yaml), from a table of cases; a passed deploy_approval can tighten the
       digest confirmation, never relax it at uat/prod.
    2  BOTH deploy reusables read KIT_RELEASE_BLOCK and KIT_ZONE_READINESS from their environment, run
       the `zone` step right after the tier is bound and before protection, verdict and login, and the
       `approval` step after the promotion gate and before login; release_gates.py is materialised;
       the posture step routes either refusal BLOCKED.
    3  THE STEPS, AS SHIPPED, under GitHub's shell: blocked platform -> refused at dev; prod with an
       unset, UNKNOWN or NOT_READY zone -> refused; READY -> proceeds; dev NOT_READY -> proceeds,
       recorded. The approval step against a recorded GitHub API (file://): an approval by the author,
       by the requester, without the digest, none at all, an unreadable API -> refused; an independent
       approval quoting the digest -> proceeds; dev -> proceeds without calling the API.

CASES (docs/PROOF_RULE.md): allowed, attack, missing-evidence and posture are each above.

EXIT 0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _step_harness as H  # noqa: E402

WFS = ['.github/workflows/reusable-deploy-appservice.yml', '.github/workflows/reusable-deploy-containerapp.yml',
       # OF-5 K-8: the static-site deploy carries the same zone and approval steps.
       '.github/workflows/reusable-deploy-staticwebapp.yml']
DIGEST = 'sha256:' + '3c' * 32
SHA, merged_head = 'a' * 40, 'b' * 40
BAD = []


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        BAD.append(label)


def table(rg):
    for v, want in (('', 'RELEASE_BLOCK_NOT_VENDED'), ('none', 'RELEASE_NOT_BLOCKED'),
                    ('platform_halted', 'RELEASE_BLOCKED_BY_PLATFORM'), ('ttl_expired', 'RELEASE_BLOCKED_BY_PLATFORM'),
                    ('budget_cap_reached', 'RELEASE_BLOCKED_BY_PLATFORM'), ('None', 'RELEASE_BLOCKED_BY_PLATFORM'),
                    ('nonsense', 'RELEASE_BLOCKED_BY_PLATFORM')):
        got = rg.decide_block(v)
        expect(got[0] == want and got[1] == (want != 'RELEASE_BLOCKED_BY_PLATFORM'),
               '1 KIT_RELEASE_BLOCK %r -> %s (%s)' % (v, want, got[0]))
    for tier, v, want in (('prod', 'READY', 'ZONE_READINESS_PERMITTED'),
                          ('uat', 'READY_WITH_EXCEPTIONS', 'ZONE_READINESS_PERMITTED'),
                          ('prod', 'NOT_READY', 'RELEASE_REFUSED_ZONE_NOT_READY'),
                          ('prod', 'UNKNOWN', 'RELEASE_REFUSED_ZONE_NOT_READY'),
                          ('prod', '', 'RELEASE_REFUSED_ZONE_NOT_READY'),
                          ('uat', 'ready', 'RELEASE_REFUSED_ZONE_NOT_READY'),
                          ('dev', 'NOT_READY', 'ZONE_READINESS_NOT_REQUIRED'),
                          ('test', '', 'ZONE_READINESS_NOT_REQUIRED'),
                          ('staging', 'READY', 'RELEASE_REFUSED_ZONE_NOT_READY')):
        got = rg.decide_zone(tier, v)
        expect(got[1] == want and got[2] == (want != 'RELEASE_REFUSED_ZONE_NOT_READY'),
               '1 tier %s KIT_ZONE_READINESS %r -> %s (%s)' % (tier, v, want, got[1]))

    def a(login, comment='', envname='production', state='approved'):
        return {'state': state, 'user': {'login': login}, 'comment': comment, 'environments': [{'name': envname}]}
    req, auth = ['dev1'], {'dev2'}
    hexd = DIGEST.split(':', 1)[1]
    cases = [
        ('independent, full digest', 'prod', [a('rev', 'approve %s' % DIGEST)], req, auth, 'required',
         'RELEASE_APPROVAL_VERIFIED'),
        ('independent, 12-hex prefix', 'prod', [a('rev', 'ok sha256:%s' % hexd[:12])], req, auth, 'required',
         'RELEASE_APPROVAL_VERIFIED'),
        ('11-hex prefix is too short', 'prod', [a('rev', 'ok %s' % hexd[:11])], req, auth, 'required',
         'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'),
        ('another digest quoted', 'prod', [a('rev', 'sha256:' + 'd' * 64)], req, auth, 'required',
         'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'),
        ('no comment', 'uat', [a('rev')], req, auth, 'required', 'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'),
        ('approved by the author', 'prod', [a('Dev2', DIGEST)], req, auth, 'required', 'SELF_DEPLOYMENT_APPROVAL'),
        ('approved by the requester', 'prod', [a('dev1', DIGEST)], req, auth, 'required', 'SELF_DEPLOYMENT_APPROVAL'),
        ('author among two approvers', 'prod', [a('rev', DIGEST), a('dev2', DIGEST)], req, auth, 'required',
         'SELF_DEPLOYMENT_APPROVAL'),
        ('approval of another environment only', 'prod', [a('rev', DIGEST, envname='test')], req, auth,
         'required', 'RELEASE_APPROVAL_ABSENT'),
        ('rejected only', 'prod', [a('rev', DIGEST, state='rejected')], req, auth, 'required',
         'RELEASE_APPROVAL_ABSENT'),
        ('no approval (admin bypass)', 'prod', [], req, auth, 'required', 'RELEASE_APPROVAL_ABSENT'),
        ('approvals unreadable', 'prod', None, req, auth, 'required', 'RELEASE_APPROVAL_NOT_ESTABLISHED'),
        ('author unreadable', 'prod', [a('rev', DIGEST)], req, None, 'required', 'RELEASE_APPROVAL_NOT_ESTABLISHED'),
        ('no requester named', 'prod', [a('rev', DIGEST)], ['', ''], auth, 'required',
         'RELEASE_APPROVAL_NOT_ESTABLISHED'),
        ('demand unreadable', 'prod', [a('rev', DIGEST)], req, auth, None, 'RELEASE_APPROVAL_NOT_ESTABLISHED'),
        ('dev, nothing demanded', 'dev', None, req, None, 'not_required', 'RELEASE_APPROVAL_NOT_REQUIRED'),
        ('dev, the register demands the digest', 'dev', [a('rev')], req, auth, 'required',
         'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'),
    ]
    for label, tier, appr, rq, au, conf, want in cases:
        got = rg.decide_approval(tier, 'production', DIGEST, appr, rq, au, conf)[0]
        expect(got == want, '1 approval: %s -> %s (%s)' % (label, want, got))
    expect(rg.confirm_demand('prod', json.dumps({'prod': {'confirm_digest': 'not_required'}})) == 'required',
           '1 a passed deploy_approval cannot relax the digest confirmation at prod')
    expect(rg.confirm_demand('dev', json.dumps({'dev': {'confirm_digest': 'required'}})) == 'required',
           '1 a passed deploy_approval can demand the digest below uat')
    expect(rg.confirm_demand('prod', '{bad') is None, '1 an unreadable deploy_approval is not established')


def wiring():
    bodies = {}
    for wf in WFS:
        doc = H.load(wf)
        job = doc['jobs']['deploy']
        steps = job['steps']
        ids = [s.get('id') for s in steps]
        jenv = job.get('env') or {}
        for var in ('KIT_RELEASE_BLOCK', 'KIT_ZONE_READINESS'):
            expect(str(jenv.get(var)) == '${{ vars.%s }}' % var, '2 %s: job env %s reads vars.%s' % (wf, var, var))
        login = next((i for i, s in enumerate(steps) if 'azure/login' in str(s.get('uses', ''))), len(steps))
        ok = all(k in ids for k in ('bind', 'zone', 'protection', 'verdict', 'approval', 'promotion_gate'))
        expect(ok, '2 %s: carries the zone and approval steps' % wf)
        if not ok:
            continue
        expect(ids.index('bind') < ids.index('zone') < ids.index('protection') < ids.index('verdict') < login,
               '2 %s: bind < zone < protection < verdict < azure/login' % wf)
        expect(ids.index('promotion_gate') < ids.index('approval') < login,
               '2 %s: promotion gate < approval < azure/login' % wf)
        mat = next((s for s in steps if s.get('name') == 'Materialise the deploy contract scripts'), {})
        expect('release_gates.py' in (mat.get('run') or ''), '2 %s: materialises release_gates.py' % wf)
        post = next((s for s in steps if s.get('id') == 'posture'), {})
        penv = str(post.get('env'))
        expect('steps.zone.outcome' in penv and 'steps.approval.outcome' in penv,
               '2 %s: the posture step reads the zone and approval outcomes' % wf)
        bodies[wf] = (H.step(wf, 'deploy', 'zone'), H.step(wf, 'deploy', 'approval'),
                      H.step(wf, 'deploy', 'posture'))
        expect('release_approval' in (job.get('outputs') or {}), '2 %s: exposes release_approval' % wf)
    runs = set((b[0].get('run'), b[1].get('run')) for b in bodies.values())
    expect(len(runs) == 1, '2 the two reusables carry the same zone and approval step bodies')
    return bodies


def api_tree(base, approvals, commits):
    root = os.path.join(base, 'api')
    if os.path.isdir(root):
        shutil.rmtree(root)
    runs = os.path.join(root, 'repos', 'o', 'r', 'actions', 'runs', '77')
    os.makedirs(runs)
    if approvals is not None:
        io.open(os.path.join(runs, 'approvals'), 'w', encoding='utf-8').write(json.dumps(approvals))
    cdir = os.path.join(root, 'repos', 'o', 'r', 'commits')
    os.makedirs(cdir)
    for sha, body in commits.items():
        io.open(os.path.join(cdir, sha), 'w', encoding='utf-8').write(json.dumps(body))
    return 'file:///' + root.replace('\\', '/').lstrip('/')


def shipped(bodies, bash):
    tmp = tempfile.mkdtemp(prefix='release-gates-')
    try:
        rt = os.path.join(tmp, 'rt')
        kit = os.path.join(rt, 'kit-deploy')
        os.makedirs(kit)
        shutil.copyfile(os.path.join(ROOT, 'scripts', 'release_gates.py'), os.path.join(kit, 'release_gates.py'))
        n = [0]

        def run(step, extra):
            extra = dict((k.upper(), v) for k, v in extra.items())   # setting names, written lower-case
            n[0] += 1
            ws = os.path.join(tmp, 'ws-%d' % n[0])
            os.makedirs(ws)
            return H.run(bash, step, {}, ws, None, dict(extra, RUNNER_TEMP=rt))
        merged = {'author': {'login': 'dev2'}, 'parents': [{'sha': 'c' * 40}, {'sha': merged_head}]}
        commits = {SHA: merged, merged_head: {'author': {'login': 'feature-dev'}, 'parents': [{'sha': 'c' * 40}]}}

        def appr(login, comment):
            return [{'state': 'approved', 'user': {'login': login}, 'comment': comment,
                     'environments': [{'name': 'production'}]}]
        for wf, (zone, approval, posture) in sorted(bodies.items()):
            short = os.path.basename(wf)
            for label, tier, block, ready, ok, gate in (
                    ('blocked platform at dev', 'dev', 'platform_halted', 'READY', False, 'ZONE_READINESS_NOT_REQUIRED'),
                    ('budget cap at prod', 'prod', 'budget_cap_reached', 'READY', False, 'ZONE_READINESS_PERMITTED'),
                    ('prod, zone unset', 'prod', 'none', '', False, 'RELEASE_REFUSED_ZONE_NOT_READY'),
                    ('prod, zone UNKNOWN', 'prod', 'none', 'UNKNOWN', False, 'RELEASE_REFUSED_ZONE_NOT_READY'),
                    ('prod, zone NOT_READY', 'prod', '', 'NOT_READY', False, 'RELEASE_REFUSED_ZONE_NOT_READY'),
                    ('prod, zone READY', 'prod', 'none', 'READY', True, 'ZONE_READINESS_PERMITTED'),
                    ('uat, zone READY_WITH_EXCEPTIONS', 'uat', '', 'READY_WITH_EXCEPTIONS', True, 'ZONE_READINESS_PERMITTED'),
                    ('dev, zone NOT_READY (recorded)', 'dev', '', 'NOT_READY', True, 'ZONE_READINESS_NOT_REQUIRED')):
                r = run(zone, {'environment_tier': tier, 'kit_release_block': block, 'kit_zone_readiness': ready})
                o = r['outputs']
                expect((r['rc'] == 0) == ok and o.get('zone_readiness_gate') == gate and o.get('release_block'),
                       '3 %s zone step: %s -> %s, %s (exit %d, %s)' % (short, label, 'proceeds' if ok else 'refused',
                                                                       gate, r['rc'], o))
            for label, tier, approvals, actor, ok, want in (
                    ('approved by the commit author', 'prod', appr('dev2', DIGEST), 'releaser', False, 'SELF_DEPLOYMENT_APPROVAL'),
                    ('approved by the merged branch author', 'prod', appr('feature-dev', DIGEST), 'releaser', False,
                     'SELF_DEPLOYMENT_APPROVAL'),
                    ('approved by the requester', 'prod', appr('releaser', DIGEST), 'releaser', False, 'SELF_DEPLOYMENT_APPROVAL'),
                    ('independent, no digest', 'prod', appr('rev', 'looks good'), 'releaser', False,
                     'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'),
                    ('no approval recorded', 'prod', [], 'releaser', False, 'RELEASE_APPROVAL_ABSENT'),
                    ('approvals unreadable', 'prod', None, 'releaser', False, 'RELEASE_APPROVAL_NOT_ESTABLISHED'),
                    ('independent, digest quoted', 'prod', appr('rev', 'release %s' % DIGEST[:19]), 'releaser', True,
                     'RELEASE_APPROVAL_VERIFIED'),
                    ('dev, API never read', 'dev', None, 'releaser', True, 'RELEASE_APPROVAL_NOT_REQUIRED')):
                api = api_tree(tmp, approvals, commits)
                r = run(approval, {'environment_tier': tier, 'deploy_environment': 'production', 'image_digest': DIGEST,
                                   'github_run_id': '77', 'github_sha': SHA, 'github_triggering_actor': actor,
                                   'github_actor': actor, 'github_repository': 'o/r', 'github_api_url': api,
                                   'gh_token': '', 'deploy_approval': ''})
                o = r['outputs']
                expect((r['rc'] == 0) == ok and o.get('release_approval') == want,
                       '3 %s approval step: %s -> %s (exit %d, %s)' % (short, label, want, r['rc'], o.get('release_approval')))
            for which in ('zone', 'approval'):
                pc = {'inputs.routing_result': 'PROCEED', 'steps.%s.outcome' % which: 'failure',
                      'steps.bind.outcome': 'success', 'job.status': 'failure', 'steps.report.outcome': 'failure',
                      'steps.report.outputs.deployment_outcome': 'DEPLOY_REFUSED', 'inputs.rollback_on_failure': 'true',
                      'inputs.slot': 'staging', 'inputs.swap_on_healthy': 'true', 'inputs.health_path': '/health',
                      'inputs.health_retries': '1', 'inputs.health_interval_seconds': '1',
                      'steps.verdict.outcome': 'success', 'steps.verdict.outputs.version_gap_ruling': 'VERSION_GAP_NOT_ENGAGED'}
                n[0] += 1
                ws = os.path.join(tmp, 'ws-%d' % n[0])
                os.makedirs(ws)
                p = H.run(bash, posture, pc, ws)
                expect(p['outputs'].get('routing_result') == 'BLOCKED',
                       '3 %s posture: a %s refusal routes BLOCKED (%s)' % (short, which, p['outputs'].get('routing_result')))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    try:
        import release_gates as rg
    except ImportError as exc:
        expect(False, '1 scripts/release_gates.py is importable (%s)' % exc)
        rg = None
    if rg is not None:
        table(rg)
    bodies = wiring()
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    if rg is not None and len(bodies) == len(WFS):
        shipped(bodies, bash)
    if BAD:
        print('FAIL: %d case(s) decided wrongly.' % len(BAD))
        return 1
    print('PASS: a release is refused before login while the landing zone has stopped the platform, while the '
          'zone is not READY for uat/prod, or when its approval is the requester\'s or the author\'s own, '
          'absent, or not bound to the digest; both deploy reusables run the checks as shipped and the '
          'posture routes each refusal BLOCKED.')
    print('      STUBBED: the approvals and commits API are recorded answers; a live uat/prod approval is owed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
