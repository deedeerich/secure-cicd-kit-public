#!/usr/bin/env python3
"""POSITIVE CONTROL: a clean consumer passes the gate and is admitted to deploy (dry run) at crawl and at walk.

WHY THIS EXISTS (owner, 2026-11-06: "I see negative testing but no positive testing.")
    The gate's proofs show what it blocks, and the deploy's proofs show what it refuses; each has its own
    "allowed" case on a stubbed value. Nothing ran the normal user's whole path: a clean scan, through the
    gate as shipped at the organisation's rung, handed to every deploy reusable's own gate step. This does,
    for crawl (the floor) and walk, stopping where a dry run stops: the deploy admits the release before
    login and touches nothing.

  POSITIVE
    P1  crawl, nothing found: the gate's own gate/posture/verdict steps route PROCEED and the verdict
        step exits 0
    P2  walk, nothing found: the same, PROCEED
    P3  each deploy reusable (Container Apps, App Service, Static Web Apps) runs its shipped
        "Gate verdict (refuse before login)" step on that verdict and ADMITS it (exit 0), at crawl and walk
  NEGATIVE (the pair that keeps P1-P3 honest)
    N1  walk with one ordinary finding routes DECISION_REQUIRED, and every deploy refuses it before login
    N2  crawl with a secret routes BLOCKED, and every deploy refuses it before login

EXIT 0 all hold   1 any does not   2 bash or PyYAML unavailable
"""
import io
import os
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[-400:]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import prove_bootstrap_failure as pbf
    import prove_gate_policy_enforcement as GP
    import _deploy_steps as D
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    steps = doc['jobs']['security-gate'].get('steps') or []
    deploys = [os.path.join(ROOT, '.github', 'workflows', n) for n in
               ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml', 'reusable-deploy-staticwebapp.yml')]
    gate_step = 'Gate verdict (refuse before login)'

    def deploy_admits(route):
        out = {}
        for wf in deploys:
            d = D.load(wf)
            _, g = D.step_named(d, gate_step)
            if g is None:
                out[os.path.basename(wf)] = 'NO GATE STEP'
                continue
            env = D.step_env(d, g, {'inputs.routing_result': route})
            rc, _o, log, _s = D.run_script(bash, g['run'], env)
            out[os.path.basename(wf)] = rc
        return out

    print('Positive control: a clean consumer through the gate to the deploy (dry run):')
    work = tempfile.mkdtemp(prefix='clean-release-')
    try:
        org_walk = GP.central([{'id': 'w', 'scope': {'org': 'acme'}, 'rung': 'walk'}])
        cases = [('crawl', GP.policy_outputs(work, None), GP.scanners()),
                 ('walk', GP.policy_outputs(work, org_walk), GP.scanners())]
        for rung, pol, seeded in cases:
            r = GP.run_job(bash, steps, pol, seeded)
            check(r['route'] == 'PROCEED' and r['verdict_rc'] == 0 and r['posture'].get('rung_effective', rung) == rung,
                  'P%s %s, nothing found: the gate routes PROCEED, verdict exit 0 (rung %s)'
                  % ('1' if rung == 'crawl' else '2', rung, r['posture'].get('rung_effective')), r['log'])
            adm = deploy_admits(r['route'] or '')
            check(all(v == 0 for v in adm.values()) and len(adm) == 3,
                  'P3 %s: every deploy reusable admits the clean verdict before login %s' % (rung, adm))
        r = GP.run_job(bash, steps, GP.policy_outputs(work, org_walk), GP.scanners('sast-semgrep'))
        adm = deploy_admits(r['route'] or '')
        check(r['route'] == 'DECISION_REQUIRED' and all(v != 0 for v in adm.values()),
              'N1 walk with a finding: DECISION_REQUIRED, and every deploy refuses it (%s, %s)' % (r['route'], adm), r['log'])
        r = GP.run_job(bash, steps, GP.policy_outputs(work, None), GP.scanners('secret-scan'))
        adm = deploy_admits(r['route'] or '')
        check(r['route'] == 'BLOCKED' and all(v != 0 for v in adm.values()),
              'N2 crawl with a secret: BLOCKED, and every deploy refuses it (%s, %s)' % (r['route'], adm), r['log'])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: a clean consumer passes the gate at crawl and walk and every deploy admits it; a finding at walk '
          'and a secret at crawl are refused.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
