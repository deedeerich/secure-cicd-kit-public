#!/usr/bin/env python3
"""The gate reads the registered rung, and the workflow cannot be handed a policy_mode or a rung.

WHY THIS EXISTS (ledger L32 wiring; ETFB section 2.2, 4.2; SINGLE_PIPELINE_TARGET.md stage 1, 5.2)

    The rung ladder, the registration reader and the derivation table are libraries with local
    proofs (lane/rung-sla). "Built as a library" is not "running": a rung held in a file that no
    run mentions is a declaration with nothing to reconcile against. This proof FAILS until the
    coordinator applies wiring/gate-rung.patch.md, and it names what is missing. Once wired, add
    it to self-test.yml next to prove_gate_routing.py.

WHAT IT CHECKS

      1  NO INPUT NAMED policy_mode OR rung, in any spelling. GitHub refuses an undeclared input
         at the call site, so not declaring one is the structural half of "a run in which
         policy_mode was supplied fails"; the runtime half is the resolver, which refuses any
         spelling it is handed.
      2  THE GATE JOB RESOLVES POLICY FIRST: a step `id: policy` using the kit's resolve-policy
         composite, before the `id: gate` step.
      3  THE COMPOSITE EXISTS, runs scripts/policy_registration.py from the kit delivered by `$/`,
         reads the registration from the fetched default branch and emits every output the
         posture step reads.
      4  THE POSTURE RECORD CARRIES THE RUNG: declared, effective, derived policy_mode, the
         resolution state, the effective minimum per control and every divergence, as job outputs
         -- ETFB 2.2: "a rung label with no emitted effective set is soft_fail_sast again".
      5  THE ROUTE FOLDS THE RESOLUTION by the registered precedence, and a verdict step exits on
         BLOCKED everywhere and on EVIDENCE_UNTRUSTED where the tier says so.
      6  target_environment IS CLASSIFIED in the posture record (totality), and the composite is
         registered in tests/reconcile_validation.py so a never-referenced composite cannot hide.
      7  DYNAMIC: the resolver's --github-output emits exactly the keys the posture step reads,
         against a throwaway git repository.

EXIT  0 wired as the patch specifies   1 not wired, with what is missing   2 could not be checked
"""
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
ACTION = os.path.join(ROOT, '.github', 'actions', 'resolve-policy', 'action.yml')
RV = os.path.join(ROOT, 'tests', 'reconcile_validation.py')

POSTURE_READS = ('policy_state', 'policy_routes_to', 'policy_rung_declared', 'policy_rung_effective',
                 'policy_rung_divergence', 'policy_policy_mode', 'policy_environment',
                 'policy_environment_tier', 'policy_team_pattern', 'policy_effective_minimum',
                 'policy_divergences', 'policy_weakenings', 'policy_unvalidated_human_workflow_paths',
                 'policy_stops_on_evidence_untrusted')
JOB_OUTPUTS = ('rung_declared', 'rung_effective', 'policy_mode', 'policy_resolution', 'effective_minimum',
               'policy_divergences', 'environment_tier', 'team_pattern', 'unvalidated_human_workflow_paths')


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    text = io.open(WF, encoding='utf-8').read()
    inputs = ((doc.get('on') or doc.get(True) or {}).get('workflow_call') or {}).get('inputs') or {}
    for name in inputs:
        norm = re.sub(r'[^a-z]', '', name.lower())
        check(norm not in ('policymode', 'rung', 'enforcementrung'),
              'input %r is declared: a rung or a policy_mode a caller can pass is a governance position '
              'expressed as a config flag' % name)
    check('target_environment' in inputs,
          'no target_environment input: the resolver needs the environment a push targets (empty means '
          'the highest environment the ref reaches unattended)')

    gate = (doc.get('jobs') or {}).get('security-gate') or {}
    steps = gate.get('steps') or []
    ids = [s.get('id') for s in steps]
    check('policy' in ids, 'security-gate has no step id: policy (the resolve-policy composite)')
    check('gate' in ids and 'policy' in ids and ids.index('policy') < ids.index('gate'),
          'the policy step must run before the gate step reads results')
    pol = next((s for s in steps if s.get('id') == 'policy'), {})
    check(str(pol.get('uses', '')).endswith('.github/actions/resolve-policy'),
          'the policy step does not use $/.github/actions/resolve-policy')
    post = next((s for s in steps if s.get('id') == 'posture'), {})
    env = post.get('env') or {}
    for key in POSTURE_READS:
        check(any('steps.policy.outputs.%s' % key in str(v) for v in env.values()),
              'the posture step does not read steps.policy.outputs.%s' % key)
    run = post.get('run') or ''
    for out in JOB_OUTPUTS:
        check(re.search(r'emit %s ' % re.escape(out), run) is not None, 'the posture step does not emit %s' % out)
        check(out in (gate.get('outputs') or {}), 'security-gate does not expose output %s' % out)
    check('posture target_environment' in run, 'target_environment is not classified in the posture record')
    check('${P_ROUTES' in run and 'rank' in run, 'the route does not fold the policy resolution by precedence')
    check('verdict' in ids, 'no verdict step exits on the folded route')
    check(os.path.isfile(ACTION), 'composite .github/actions/resolve-policy/action.yml does not exist')
    if os.path.isfile(ACTION):
        act = io.open(ACTION, encoding='utf-8').read()
        check('scripts/policy_registration.py' in act and '--github-output' in act,
              'the composite does not run scripts/policy_registration.py with --github-output')
        # KDEC-022 item 2: cloned blob-less WITH history (the renewal counts come from git), read at
        # the clone's HEAD -- the default branch, never the checkout.
        check('git clone' in act and '--filter=blob:none' in act and '--branch "${DEFAULT_BRANCH}"' in act
              and '--default-ref HEAD' in act,
              'the composite does not read the registration from the fetched default branch')
    check("'action:resolve-policy'" in io.open(RV, encoding='utf-8').read().replace('"', "'"),
          'action:resolve-policy is not registered in tests/reconcile_validation.py')

    # 7  Dynamic: the CLI emits the keys the posture step reads.
    work = tempfile.mkdtemp(prefix='gate-rung-')
    try:
        repo = os.path.join(work, 'r')
        os.makedirs(os.path.join(repo, '.security'))
        reg = json.load(io.open(os.path.join(ROOT, 'templates', 'policy-registration.example.json'), encoding='utf-8'))
        io.open(os.path.join(repo, '.security', 'policy-registration.json'), 'w', encoding='utf-8').write(json.dumps(reg))
        g = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
             '-c', 'init.defaultBranch=main']
        subprocess.run(g + ['init', '-q'], cwd=repo, check=True)
        subprocess.run(g + ['add', '-A'], cwd=repo, check=True)
        subprocess.run(g + ['commit', '-qm', 'x'], cwd=repo, check=True)
        out = os.path.join(work, 'out.txt')
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'), '--repo', repo,
                            '--default-ref', 'main', '--event', 'push', '--github-output', out],
                           capture_output=True, text=True)
        keys = [l.split('=', 1)[0] for l in io.open(out, encoding='utf-8').read().splitlines() if '=' in l]
        for key in POSTURE_READS:
            check(key in keys, 'the resolver did not emit %s for the posture step to read' % key)
        check(p.returncode == 0, 'the resolver refused the shipped example: %s' % p.stdout[-300:])
    except (OSError, subprocess.CalledProcessError) as exc:
        print('UNKNOWN: fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        print('NOT WIRED (%d item(s)); apply wiring/gate-rung.patch.md:' % len(fails))
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: no rung or policy_mode input is declared; the gate resolves policy from the protected '
          'branch before reading results; the posture record carries declared, effective, policy_mode, '
          'the resolution, the effective minimum and every divergence as outputs; the route folds the '
          'resolution; a verdict step exits on it; the composite is registered; the resolver emits every '
          'key the posture step reads.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
