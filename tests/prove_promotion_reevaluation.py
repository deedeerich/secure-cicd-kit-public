#!/usr/bin/env python3
"""A promotion binds to the evidence of the exact digest and re-evaluates it; it never rescans the code.

WHY THIS EXISTS (owner, 2026-11-18, approved 2026-11-24, KDEC-070): "deploys bind to the evidence of the exact
artifact (no rescan at promotion); cancelled/missing required evidence never passes (tested at the gate
boundary); outcome and cause are separate fields." The brief for this revision adds what promotion still
RE-EVALUATES against that exact digest: current vulnerability intelligence (new advisories against the recorded
SBOM), evidence freshness, exception validity and expiry, approval state, and the target environment's policy.

scripts/promotion.py judge() and gate-decide hold it:

  POSITIVE
    B1  the promotion record binds its evidence to the digest (provenance.evidence_binding: security gate,
        SBOM, attestation, each with state, digest, produced_at; schema unchanged at the top level); a record written before this change derives the
        same binding from the fields it already carries
    R1  a promotion whose bound evidence is complete, fresh, on this digest, with valid exceptions, the
        approval its predecessor needs and an acceptable gate route, is PROMOTION_ALLOWED: outcome ALLOWED,
        no cause
    R2  new advisories against the recorded SBOM still refuse (the existing re-scan, unchanged)
  NEGATIVE (each named by its own cause; outcome and cause are separate fields)
    E1  required evidence MISSING or CANCELLED never passes                 PROMOTION_REFUSED_EVIDENCE_MISSING
    E2  evidence bound to another digest                                    PROMOTION_REFUSED_EVIDENCE_DIGEST
    E3  evidence older than the target environment allows, or undated       PROMOTION_REFUSED_EVIDENCE_STALE
    E4  an exception the digest relied on expired, or was revoked           PROMOTION_REFUSED_EXCEPTION_INVALID
    E5  the predecessor's approval was rejected, or uat's is not APPROVED   PROMOTION_REFUSED_APPROVAL_STATE
    E6  the target's policy refuses the recorded gate route or an advisory
        cause, or the target policy could not be read                       PROMOTION_REFUSED_TARGET_POLICY
    E7  break-glass lifts none of E1, E2, E4, E5, E6
  GATE BOUNDARY (gate-decide, the step the deploy runs before login)
    G1  a cancelled security gate and a missing SBOM each exit 1, write promotion-gate.json with outcome
        REFUSED and the cause in `causes`, and print the refusal; the complete case exits 0, outcome ALLOWED
    G2  the inlined copies in the three deploy reusables match scripts/promotion.py (inline_deploy_scripts)

EXIT 0 all hold   1 any does not
"""
import copy
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import promotion as PR  # noqa: E402

FAILS = []
D1, D2 = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64
NOW = PR.parse_ts('2026-11-25T12:00:00Z')
SIGNER = 'org/app/.github/workflows/build.yml@refs/heads/main'


def check(cond, label, detail=''):
    print('  %s  %s%s' % ('PASS' if cond else 'FAIL', label, ('  -- %s' % detail) if (detail and not cond) else ''))
    if not cond:
        FAILS.append(label)


def binding(digest=D1, at='2026-11-20T10:00:00Z', gate='COMPLETE', sbom='COMPLETE', att='COMPLETE', route='PROCEED'):
    return {'digest': digest, 'items': [
        {'kind': 'security-gate', 'state': gate, 'digest': digest, 'produced_at': at, 'ref': 'run 41',
         'route': route},
        {'kind': 'sbom', 'state': sbom, 'digest': digest, 'produced_at': at, 'ref': 'sha256:' + 'f' * 64},
        {'kind': 'attestation', 'state': att, 'digest': digest, 'produced_at': at, 'ref': 'ATTESTATION_VERIFIED'}]}


def rec(digest=D1, tier='test', envname='test', at='2026-11-24T12:00:00Z', approval_state='NONE_REQUIRED_OR_RECORDED',
        ev=None, exceptions=None, causes=(), route='PROCEED'):
    r = {'schema': PR.SCHEMA, 'state': PR.VERIFIED, 'artifact': {'digest': digest, 'sbom_sha256': 'f' * 64},
         'environment': {'name': envname, 'tier': tier, 'adapter': 'containerapp',
                         'target_resource_id': '/subs/x/rg/rg-a/containerApps/web'},
         'provenance': {'source_ref': 'refs/heads/main', 'build_workflow': SIGNER, 'gate_routing_result': route,
                        'advisory_causes': list(causes), 'attestation_outcome': 'ATTESTATION_VERIFIED',
                        'evidence_binding': binding(digest, route=route) if ev is None else ev},
         'conditions': {'missing': []}, 'validity': {'verified_at': at}, 'run': {'id': '7'},
         'approval': {'state': approval_state, 'approvers': [{'login': 'approver-a', 'state': 'approved'}]},
         '_artifact': {'head_branch': 'main'}}
    if exceptions is not None:
        r['provenance']['exceptions_relied_on'] = exceptions
    return r


def ctx(**o):
    c = {'digest': D1, 'required_predecessor': 'test', 'source_environment': 'test', 'source': rec(),
         'history': [], 'revocations': [], 'rescan': {'state': 'COMPLETE', 'critical': [], 'high': []},
         'kev': {'state': 'AVAILABLE', 'blocking': []}, 'attestation': 'ATTESTATION_VERIFIED',
         'release_path': 'normal', 'exception': {}, 'now': NOW, 'destination_tier': 'uat',
         'expected_target': '/subs/x/rg/rg-a/containerapps/web'}
    c.update(o)
    return c


def codes(res):
    return [r['code'] for r in res['refusals']]


def pure():
    print('R / E: the judgement')
    res = PR.judge(ctx())
    check(res['verdict'] == 'PROMOTION_ALLOWED' and res['outcome'] == 'ALLOWED' and res['causes'] == [] and
          res['cause'] is None, 'R1 complete, fresh, bound evidence: ALLOWED, no cause', res)
    res = PR.judge(ctx(rescan={'state': 'COMPLETE', 'critical': [], 'high': ['CVE-2026-9@zlib:1']}))
    check('PROMOTION_REFUSED_NEW_FINDING' in codes(res) and res['outcome'] == 'REFUSED',
          'R2 a new advisory against the recorded SBOM refuses (re-evaluated, never rescanned)', res)
    old = rec(ev={})
    old['provenance'].pop('evidence_binding')
    old['artifact']['version_metadata'] = json.dumps({'built_at': '2026-11-20T10:00:00Z'})
    b = PR.evidence_binding_of(old)
    check(sorted(i['kind'] for i in b['items']) == ['attestation', 'sbom', 'security-gate'] and
          all(i['state'] == 'COMPLETE' and i['digest'] == D1 for i in b['items']),
          'B1 a record from before this change derives its binding from the fields it carries', b)
    check(PR.judge(ctx(source=old))['verdict'] == 'PROMOTION_ALLOWED', 'B1 ... and promotes on it')
    cases = [
        ('E1 security gate MISSING', dict(source=rec(ev=binding(gate='MISSING'))), 'PROMOTION_REFUSED_EVIDENCE_MISSING'),
        ('E1 security gate CANCELLED', dict(source=rec(ev=binding(gate='CANCELLED'))), 'PROMOTION_REFUSED_EVIDENCE_MISSING'),
        ('E1 SBOM evidence MISSING', dict(source=rec(ev=binding(sbom='MISSING'))), 'PROMOTION_REFUSED_EVIDENCE_MISSING'),
        ('E1 no binding at all and no fields', dict(source=dict(rec(ev={}), provenance={'source_ref': 'refs/heads/main',
                                                                                         'build_workflow': SIGNER},
                                                                artifact={'digest': D1})),
         'PROMOTION_REFUSED_EVIDENCE_MISSING'),
        ('E2 evidence bound to another digest', dict(source=rec(ev=binding(digest=D2))), 'PROMOTION_REFUSED_EVIDENCE_DIGEST'),
        ('E3 evidence 40 days old (uat allows 30)', dict(source=rec(ev=binding(at='2026-10-16T10:00:00Z'))),
         'PROMOTION_REFUSED_EVIDENCE_STALE'),
        ('E3 evidence undated', dict(source=rec(ev=binding(at=''))), 'PROMOTION_REFUSED_EVIDENCE_STALE'),
        ('E4 relied-on exception expired', dict(source=rec(exceptions=[{'ref': 'EXC-1', 'expires': '2026-11-24',
                                                                        'authority': 'sec'}])),
         'PROMOTION_REFUSED_EXCEPTION_INVALID'),
        ('E4 relied-on exception revoked', dict(source=rec(exceptions=[{'ref': 'EXC-2', 'expires': '2026-12-31',
                                                                        'authority': 'sec'}]),
                                                revocations=[{'kind': 'exception', 'match': 'EXC-2', 'reason': 'withdrawn'}]),
         'PROMOTION_REFUSED_EXCEPTION_INVALID'),
        ('E4 relied-on exception with no expiry', dict(source=rec(exceptions=[{'ref': 'EXC-3', 'expires': ''}])),
         'PROMOTION_REFUSED_EXCEPTION_INVALID'),
        ('E5 the predecessor approval was rejected', dict(source=rec(approval_state='REJECTED')),
         'PROMOTION_REFUSED_APPROVAL_STATE'),
        ('E5 prod from uat whose approval is not APPROVED',
         dict(source=rec(tier='uat', envname='uat'), source_environment='uat', required_predecessor='uat',
              destination_tier='prod'), 'PROMOTION_REFUSED_APPROVAL_STATE'),
        ('E6 the target refuses an advisory cause the build carried',
         dict(source=rec(causes=['SCANNER_DID_NOT_RUN'], route='PROCEED_WITH_ADVISORY'),
              target_policy={'required_evidence': ['security-gate'], 'max_evidence_age_days': 30,
                             'refuse_advisory_causes': ['SCANNER_DID_NOT_RUN']}), 'PROMOTION_REFUSED_TARGET_POLICY'),
        ('E6 a gate route the target does not accept', dict(source=rec(route='DECISION_REQUIRED')),
         'PROMOTION_REFUSED_TARGET_POLICY'),
        ('E6 the target policy could not be read', dict(target_policy_error='HTTP 500'), 'PROMOTION_REFUSED_TARGET_POLICY'),
    ]
    for label, over, want in cases:
        res = PR.judge(ctx(**over))
        check(want in codes(res) and res['outcome'] == 'REFUSED' and want in res['causes'] and res['cause'],
              '%s: %s (outcome REFUSED, cause separate)' % (label, want), res)
    exc = {'reason': 'incident 7', 'authority': 'release-approvers', 'exception_ref': 'EXC-BG',
           'expires': '2026-11-27'}
    for label, over, want in cases:
        if not label.startswith(('E1', 'E2', 'E4', 'E5', 'E6')):
            continue
        res = PR.judge(ctx(release_path='break-glass', exception=exc, **over))
        if want not in codes(res):
            check(False, 'E7 break-glass lifted %s (%s)' % (want, label), res)
            break
    else:
        check(True, 'E7 break-glass lifts none of the evidence, exception, approval or target-policy refusals')
    res = PR.judge(ctx(release_path='break-glass', exception=exc,
                       source=rec(ev=binding(at='2026-10-16T10:00:00Z'))))
    check('PROMOTION_REFUSED_EVIDENCE_STALE' not in codes(res) and
          any(o['code'] == 'PROMOTION_REFUSED_EVIDENCE_STALE' for o in res['overridden']),
          'E7 break-glass may lift stale evidence, and says so (overridden)', res)
    res = PR.judge(ctx(destination_tier='test', source=rec(ev={})))
    check(res['verdict'] == 'PROMOTION_ALLOWED' or 'PROMOTION_REFUSED_EVIDENCE_MISSING' not in codes(res),
          'R1 below uat the default target policy requires no binding (dev and test are ungated)', res)


def boundary():
    print('G: the gate boundary (gate-decide, before login)')
    script = os.path.join(ROOT, 'scripts', 'promotion.py')
    for label, source, want_rc, want_cause in (
            ('complete', rec(), 0, None),
            ('cancelled security gate', rec(ev=binding(gate='CANCELLED')), 1, 'PROMOTION_REFUSED_EVIDENCE_MISSING'),
            ('missing SBOM evidence', rec(ev=binding(sbom='MISSING')), 1, 'PROMOTION_REFUSED_EVIDENCE_MISSING')):
        work = tempfile.mkdtemp()
        os.makedirs(os.path.join(work, 'promotion'))
        col = {'run_id': '41', 'source_environment': 'test', 'required_predecessor': 'test',
               'expected_source_target': '/subs/x/rg/rg-a/containerapps/web', 'source': source,
               'source_error': '', 'history': [], 'revocations': [],
               'rescan': {'state': 'COMPLETE', 'why': '', 'critical': [], 'high': []},
               'target_policy': None, 'target_policy_error': ''}
        json.dump(col, io.open(os.path.join(work, 'promotion', 'collected.json'), 'w'))
        # Settings are written lower-case and upper-cased on use, as deploy_contract.env reads them.
        sets = dict(kit_promotion_now='2026-11-25T12:00:00Z', image_digest=D1, kev_state='AVAILABLE',
                    kev_blocking='', attestation_outcome='ATTESTATION_VERIFIED', release_path='normal',
                    environment_tier='uat', promote_from_environment='test', promotion_predecessor='test',
                    github_output=os.path.join(work, 'out'), github_step_summary=os.path.join(work, 'sum'),
                    runner_temp=work)
        env = dict(os.environ, **dict((k.upper(), v) for k, v in sets.items()))
        p = subprocess.run([sys.executable, script, 'gate-decide'], cwd=work, env=env, capture_output=True, text=True,
                           timeout=120)
        try:
            gate = json.load(io.open(os.path.join(work, 'deploy-evidence', 'promotion-gate.json'), encoding='utf-8'))
        except (OSError, ValueError):
            gate = None
        ok = (p.returncode == want_rc and gate and gate.get('outcome') == ('ALLOWED' if want_rc == 0 else 'REFUSED')
              and (want_cause is None or want_cause in gate.get('causes', [])) and
              (want_cause is None or want_cause in p.stdout))
        check(ok, 'G1 %s: exit %d, outcome %s%s' % (label, want_rc, 'ALLOWED' if want_rc == 0 else 'REFUSED',
                                                     ', cause ' + want_cause if want_cause else ''),
              (p.returncode, gate, p.stdout[-400:], p.stderr[-400:]))
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'inline_deploy_scripts.py'), '--check'],
                       cwd=ROOT, capture_output=True, text=True, timeout=300)
    check(p.returncode == 0, 'G2 the inlined copies in the deploy reusables match scripts/promotion.py',
          (p.stdout + p.stderr)[-400:])


def main():
    print('Promotion re-evaluation (KDEC-070): bound to the digest\'s evidence, re-judged, never rescanned')
    pure()
    boundary()
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: evidence bound to the digest; freshness, exceptions, approval, target policy and new advisories '
          're-evaluated; cancelled or missing evidence never passes at the gate boundary; outcome and cause separate.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
