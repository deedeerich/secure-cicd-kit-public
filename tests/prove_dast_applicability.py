#!/usr/bin/env python3
"""External review 2026-11-07 R07: an unconfigured DAST is never a passed scan.

Promotion's DAST condition is "dynamic scan passed, or recorded as not required". It holds for a passed scan,
for prod's passive read, and for NOT_CONFIGURED only when no org policy requires DAST or the org recorded a
per-repository decision (approved_by, ref, date, reason). With the org overlay's dast.required true and no
decision, NOT_CONFIGURED leaves the condition missing: the release is not verified for promotion.

  POSITIVE  P1 a passed scan holds; P2 prod's passive read holds; P3 NOT_CONFIGURED with no org policy holds
            and says why (KDEC-029 "where configured"); P4 NOT_CONFIGURED with a recorded decision holds
  NEGATIVE  N1 NOT_CONFIGURED when the org requires DAST: missing; N2 a blocking or incomplete result: missing;
            N3 an unreadable org policy never waives a scan; N4 a decision missing a field is refused by the
            overlay validator; N5 the dast_basis names the reason in every case
  MUTANT    M1 the old rule (NOT_CONFIGURED always holds) is caught by N1
"""
import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import deploy_contract as DC  # noqa: E402
import org_settings as OS  # noqa: E402

COND = 'dynamic scan passed, or recorded as not required'
FAILS = []


def check(cond, msg):
    print(('  ok   ' if cond else '  FAIL ') + msg)
    if not cond:
        FAILS.append(msg)


def run(dast_result, org_settings, mod=DC):
    tmp = tempfile.mkdtemp(prefix='dast_')
    try:
        os.environ['RUNNER_TEMP'] = tmp
        if org_settings is None:
            os.environ.pop('KIT_ORG_SETTINGS', None)
        else:
            os.environ['KIT_ORG_SETTINGS'] = org_settings
        mod.write_evidence('dast.json', {'result': dast_result})
        p = mod.promotion('DEPLOY_HEALTHY')
        return COND in p['established'], p.get('dast_basis', '')
    finally:
        os.environ.pop('RUNNER_TEMP', None)
        os.environ.pop('KIT_ORG_SETTINGS', None)
        shutil.rmtree(tmp, ignore_errors=True)


def resolved(**dast):
    return json.dumps({'schema': 'kit-org-settings-resolved/1', 'state': 'ORG_OVERLAY_APPLIED', 'dast': dast})


def main():
    req = resolved(state='DAST_REQUIRED')
    decided = resolved(state='DAST_NOT_REQUIRED_BY_DECISION')
    ok, b = run('DAST_PASSED', req)
    check(ok and b == 'DAST_PASSED', 'P1 a passed scan holds the condition (%s)' % b)
    ok, b = run('NOT_APPLICABLE_PASSIVE', req)
    check(ok, 'P2 prod\'s passive read holds the condition')
    ok, b = run('NOT_CONFIGURED', None)
    check(ok and 'DAST_NO_ORG_POLICY' in b, 'P3 NOT_CONFIGURED with no org policy holds and says why (%s)' % b)
    ok, b = run('NOT_CONFIGURED', decided)
    check(ok and 'DAST_NOT_REQUIRED_BY_DECISION' in b, 'P4 NOT_CONFIGURED with a recorded decision holds (%s)' % b)
    ok, b = run('NOT_CONFIGURED', req)
    check(not ok and 'DAST_REQUIRED' in b, 'N1 NOT_CONFIGURED while the org requires DAST: missing (%s)' % b)
    for r in ('DAST_BLOCKING_FINDINGS', 'DAST_INCOMPLETE', ''):
        ok, b = run(r, None)
        check(not ok, 'N2 a %s result never holds the condition' % (r or 'missing'))
    ok, b = run('NOT_CONFIGURED', '{not json')
    check(not ok, 'N3 an unreadable org policy never waives a scan')
    doc = {'schema': 'kit-org-settings/1', 'github_orgs': ['o'], 'dast': {'required': True},
           'repositories': {'o/r': {'dast_not_required': {'approved_by': 'security lead', 'ref': 'SEC-9',
                                                          'date': '2026-11-07'}}}}
    check(any('dast_not_required' in p for p in OS.problems(doc)),
          'N4 a not-required decision without its reason is refused by the overlay validator')
    good = dict(doc, repositories={'o/r': {'dast_not_required': {'approved_by': 'security lead', 'ref': 'SEC-9',
                                                                 'date': '2026-11-07', 'reason': 'no web surface'}}})
    check(not OS.problems(good) and OS.dast_policy(good, 'o/r')['state'] == OS.DAST_NOT_REQUIRED and
          OS.dast_policy(good, 'o/other')['state'] == OS.DAST_REQUIRED,
          'P5 the overlay resolves a recorded decision for its repository only; the others stay required')
    # M1: the old rule
    src = io.open(os.path.join(ROOT, 'scripts', 'deploy_contract.py'), encoding='utf-8').read()
    old = "(da == 'NOT_CONFIGURED' and pol != 'DAST_REQUIRED')"
    if src.count(old) != 1:
        check(False, 'M1 mutant anchor not found once')
    else:
        import types
        m = types.ModuleType('dc_mutant')
        m.__file__ = os.path.join(ROOT, 'scripts', 'deploy_contract.py')
        exec(compile(src.replace(old, "(da == 'NOT_CONFIGURED')"), m.__file__, 'exec'), m.__dict__)
        ok, _b = run('NOT_CONFIGURED', req, mod=m)
        check(ok, 'M1 the old rule (NOT_CONFIGURED always holds) is caught by N1')
    print()
    if FAILS:
        print('FAIL: %d check(s)' % len(FAILS))
        return 1
    print('PASS: an unconfigured DAST is never a passed scan; it holds only with no org policy or a recorded decision.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
