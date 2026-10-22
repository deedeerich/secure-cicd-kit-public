#!/usr/bin/env python3
"""Crawl is the absolute floor: no run input, weakening or register entry produces enforcement below
it. (KDEC-018 item 1, owner 2026-10-22: "You can't drop below crawl ever. There is no way around
crawl to a lower anything. Only up." Lane L-FX.)

WHAT CRAWL IS (KDEC-017 item 1)

    Block on any secret, and on the kit being unable to run or trust its own scan (a crash,
    COLLECTION_FAILED, a hollow or unreadable scan, a bootstrap failure, an unresolved policy).

WHAT THIS PROVES, against the security gate's own shipped steps (gate -> posture -> verdict) and the
secret-scan job as shipped

    K1  THE SECRET SCAN IS NEVER NARROWED. Its job hands the composite the repository root, not
        the caller's `paths` (which narrows the other scanners): a secret outside `paths` is still
        scanned. Before lane L-FX, `paths: src` scanned only src for secrets -- a way below crawl.
    K2  THE SECRET SCAN READS NO WEAKENING INPUT. The only inputs its job reads are the ones that
        can only WIDEN it (scan_git_history) or ADD files to it (test_only_seed_artifact, add-only,
        tests/prove_test_only_seeds_add_only.py).
    K3  EVERY WEAKENING INPUT, ATTRIBUTED AND UNEXPIRED, STILL BLOCKS A SECRET: advisory_mode,
        soft_fail_sast, paths, language, iac_mode, enable_sbom, enable_malicious_pkg_scan,
        fail_on_severity, semgrep_config, codeql_queries, enforce_lint -> routing_result BLOCKED,
        verdict exit 1.
    K4  ... AND STILL STOPS ON A SCAN THE KIT COULD NOT RUN OR TRUST: the same inputs with a crashed
        scanner -> EVIDENCE_UNTRUSTED, verdict exit 1, at a dev tier as at prod.
    K5  THE REGISTER CANNOT GO BELOW CRAWL (tests/prove_authority_floor.py A6): no rung below
        crawl, secrets never soften -- asserted here against the resolver too, so this one proof
        names every path.

EXIT  0 proven   1 a path drops below crawl (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_gate_policy_enforcement as E  # noqa: E402
import prove_gate_routing as G  # noqa: E402

ATTRIB = {'weakening_reason': 'adoption: a narrower scan while the team onboards',
          'weakening_authority': 'Dana Example (security lead)', 'weakening_exception_ref': 'SEC-77',
          'weakening_expires': '2099-01-31'}
# Every input the posture record classes as a weakening of some control, set to a weaker value.
WEAKENINGS = {
    'advisory_mode': 'true', 'soft_fail_sast': 'true', 'paths': 'src', 'language': 'python',
    'iac_mode': 'disabled', 'enable_sbom': 'false', 'enable_malicious_pkg_scan': 'false',
    'fail_on_severity': 'CRITICAL', 'semgrep_config': 'p/default', 'codeql_queries': 'default',
    'enforce_lint': 'false',
}
SECRET_JOB_ALLOWED_INPUTS = {'scan_git_history', 'test_only_seed_artifact'}


def run_job(bash, steps, pol, seeded, inputs):
    """gate -> posture -> verdict with the caller's INPUTS reaching both the gate and the posture."""
    gate = E.step(steps, 'gate')
    values = dict(seeded, **pol)
    values.update(('inputs.%s' % k, v) for k, v in inputs.items())
    body, _seen = pbf.substitute(gate.get('run') or '', values)
    genv, _u = pbf.resolve_env(gate.get('env'), values)
    grc, gout, glog, _gs = pbf.run(bash, body, genv)
    post = E.step(steps, 'posture')
    penv, unknown = G.resolve_env(post.get('env'), inputs, gout, pol)
    _prc, pout, plog, _ps = pbf.run(bash, post.get('run') or '', penv)
    ver = E.step(steps, 'verdict')
    vvals = dict(pol, **dict(('steps.posture.outputs.%s' % k, v) for k, v in pout.items()))
    venv, _u = pbf.resolve_env(ver.get('env'), vvals)
    vrc, _vo, vlog, _vs = pbf.run(bash, ver.get('run') or 'exit 99', venv)
    return {'gate_rc': grc, 'route': pout.get('routing_result'), 'verdict_rc': vrc,
            'attribution': pout.get('weakening_attribution'), 'unknown': unknown,
            'log': glog[-300:] + plog[-300:] + vlog[-200:]}


def main():
    try:
        import yaml
        import policy_registration as pr
        import rung_ladder as rl
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    fails = []

    # ---- K1 / K2: the secret-scan job as shipped ---------------------------------------------------
    job = (doc.get('jobs') or {}).get('secret-scan') or {}
    scan = next((s for s in job.get('steps') or [] if s.get('id') == 'scan'), None)
    if not scan:
        print('FAIL: the secret-scan job has no `scan` step')
        return 1
    given = str((scan.get('with') or {}).get('paths', ''))
    if given.strip() != '.':
        fails.append('K1: the secret scan is handed paths=%r: a caller narrowing `paths` narrows the secret '
                     'scan, and a secret outside it is never scanned -- below crawl' % given)
    text = yaml.safe_dump(job)
    read = set(re.findall(r'inputs\.([A-Za-z0-9_]+)', text))
    extra = sorted(read - SECRET_JOB_ALLOWED_INPUTS)
    if extra:
        fails.append('K2: the secret-scan job reads input(s) %s; only %s (which can only widen or add to '
                     'the scan) may reach it' % (', '.join(extra), ', '.join(sorted(SECRET_JOB_ALLOWED_INPUTS))))

    # ---- K3 / K4: every weakening input, through the gate ------------------------------------------
    steps = doc['jobs']['security-gate'].get('steps') or []
    base = dict(G.BASELINE, **ATTRIB)
    work = tempfile.mkdtemp(prefix='crawl-floor-')
    try:
        for tier in ('dev', 'prod'):
            pol = E.policy_outputs(work, None, environment=tier)
            if not pol.get('steps.policy.outputs.policy_state'):
                print('UNKNOWN: the resolver emitted no policy_state')
                return 2
            for name, val in sorted(WEAKENINGS.items()):
                inputs = dict(base, **{name: val})
                r = run_job(bash, steps, pol, E.scanners('secret-scan'), inputs)
                print('  %-4s %-26s secret -> route=%-20s verdict=%d   crash -> '
                      % (tier, '%s=%s' % (name, val), r['route'], r['verdict_rc']), end='')
                if r['unknown']:
                    fails.append('%s %s: the posture reads %s, unmodelled' % (tier, name, r['unknown']))
                if r['route'] != 'BLOCKED' or r['verdict_rc'] == 0:
                    fails.append('K3: %s=%s (attributed, unexpired) at %s let a secret through: routing_result=%s '
                                 'verdict exit %d\n%s' % (name, val, tier, r['route'], r['verdict_rc'], r['log']))
                c = run_job(bash, steps, pol, E.scanners(failed=('sast-go',)), inputs)
                print('route=%-20s verdict=%d' % (c['route'], c['verdict_rc']))
                if c['route'] != 'EVIDENCE_UNTRUSTED' or c['verdict_rc'] == 0:
                    fails.append('K4: %s=%s (attributed, unexpired) at %s let a crashed scan through: '
                                 'routing_result=%s verdict exit %d\n%s'
                                 % (name, val, tier, c['route'], c['verdict_rc'], c['log']))
    except (OSError, ValueError) as exc:
        print('UNKNOWN: the fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # ---- K5: the register --------------------------------------------------------------------------
    def central(policies):
        return {'schema_version': 2, 'register_id': 'k5',
                'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
                'policies': policies}
    dec = {'authority': 'Dana Example', 'reason': 'r', 'decided_on': '2026-10-20', 'expires': '2099-01-31',
           'environment_reviewers': ['platform-approvers']}
    for tier in rl.tier_order:
        r = pr.resolve(None, None, 'acme/x', tier, 'push', {}, '2026-10-22')
        if r['job_minimums'].get('secret-scan') != 'BLOCKED':
            fails.append('K5: the kit default does not block secrets at %s' % tier)
    for fields in ({'rung': 'off'}, {'controls': {'secrets': 'PROCEED_WITH_ADVISORY'}},
                   {'controls': {'secret-scan': 'DECISION_REQUIRED'}}):
        r = pr.resolve(central([dict({'id': 'x', 'scope': {'org': 'acme'}, 'decision': dec}, **fields)]),
                       None, 'acme/x', 'prod', 'push', {}, '2026-10-22')
        if r['state'] == rl.POLICY_RESOLVED:
            fails.append('K5: a register entry %r below crawl resolved' % fields)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: crawl is the absolute floor -- the secret scan always covers the repository root and reads no '
          'weakening input; every weakening input, attributed and unexpired, still BLOCKS a secret and still '
          'stops on a scan the kit could not run or trust, at dev and at prod; and no register entry goes '
          'below crawl.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
