#!/usr/bin/env python3
"""Every exception shows its history, and renewals are counted and capped. (KDEC-018 item 4, owner
2026-10-22: "when they resurface it needs to be clear they were exempted previously and shown.
Because endless exemptions/exceptions are not a thing." Lane L-FX.)

THE EXCEPTIONS WITH AN EXPIRY THAT THE KIT HONOURS (each covered here)

    secret_exceptions items     the register; the gate excepts ONE secret finding
    policy decisions            the register; the authority's softening of the kit default deploy
                                approval (the only softening KDEC-018 leaves) -- decision.renews
    version-gap exceptions      the deploy's weakening record at uat/prod (KDEC-014) --
                                weakening_renews beside weakening_expires

WHAT IT PROVES (scripts/exception_history.py; scripts/policy_registration.py; the security gate's
own gate step; scripts/run_record.py; both deploy reusables' verdict step -- all as shipped)

    H1  no `renews` is shown as "first exception"; a history is shown as "previously excepted N
        time(s) since <date>, tickets ..., approvers ..." -- in the resolver's applied record, the
        gate summary, the gate's secret_exceptions_applied output and the run record
    H2  renewals within the cap are applied; over the cap the exception is refused by name,
        EXCEPTION_RENEWAL_LIMIT, and the finding reverts to its normal routing (a secret BLOCKS)
    H3  the cap is numbers.max_exception_renewals in the CENTRAL register, kit default 2, an integer
        0..5 -- never unlimited; out of range, not an integer, or set in a repository file, the
        register is refused (REGISTRATION_UNAVAILABLE)
    H4  a history the kit cannot read is not "no history": the secret exception is
        SECRET_EXCEPTION_UNATTRIBUTED, the decision POLICY_DECISION_UNATTRIBUTED
    H5  a policy decision softening over the cap is refused (EXCEPTION_RENEWAL_LIMIT,
        DECISION_REQUIRED) and the softening does not apply; within the cap the weakening row
        carries its history, and the run record lists it (policy_exceptions)
    H6  the deploy's version-gap exception: within the cap accepted with its history shown; over
        the cap, unreadable, or over a lower cap the caller passes -> VERSION_GAP_REFUSED naming
        EXCEPTION_RENEWAL_LIMIT; a cap ABOVE the kit default is not honoured by the deploy (it holds
        the stronger)
    H7  --validate names an over-cap exception; EXCEPTION_RENEWAL_LIMIT is registered

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
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
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _deploy_steps as D  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_gate_policy_enforcement as E  # noqa: E402

TODAY = '2026-10-22'
LIMIT = 'EXCEPTION_RENEWAL_LIMIT'
G1 = {'ticket': 'SEC-1200', 'approver': 'Robin Example', 'from': '2026-01-10', 'expires': '2026-04-10'}
G2 = {'ticket': 'SEC-1311', 'approver': 'Dana Example', 'from': '2026-04-10', 'expires': '2026-07-10'}
G3 = {'ticket': 'SEC-1420', 'approver': 'Dana Example', 'from': '2026-07-10', 'expires': '2026-10-10'}
HISTORY_2 = 'previously excepted 2 time(s) since 2026-01-10, tickets SEC-1200, SEC-1311, approvers Robin Example, Dana Example'
VERDICT_STEP = 'Gate verdict (refuse before login)'


def sx(**over):
    item = {'finding': E.fp_a, 'ticket': 'SEC-1500', 'explanation': 'fixture credential; rotation tracked',
            'approver': 'Dana Example', 'expires': '2099-01-31', 'environment_reviewers': ['platform-approvers']}
    item.update(over)
    return item


def main():
    try:
        import policy_registration as pr
        import rung_ladder as rl
        import yaml
        import jsonschema
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def res(cen, repo_doc=None):
        return pr.resolve(cen, repo_doc, E.REPOSITORY, 'prod', 'push', {}, TODAY)

    # ---- H1 / H2: the resolver -----------------------------------------------------------------------
    r = res(E.sx_central([sx()]))
    applied = r.get('secret_exceptions') or []
    check(r['state'] == rl.POLICY_RESOLVED and len(applied) == 1 and applied[0].get('history') == 'first exception'
          and applied[0].get('renewals') == 0,
          'H1: an exception with no history is not shown as the first exception: %r' % applied)
    r = res(E.sx_central([sx(renews=[G2, G1])]))
    applied = r.get('secret_exceptions') or []
    check(len(applied) == 1 and applied[0].get('history') == HISTORY_2 and applied[0].get('renewals') == 2,
          'H1/H2: a twice-renewed exception (cap 2) is not applied with its history: %r %r'
          % (applied, r.get('secret_exception_refusals')))
    r = res(E.sx_central([sx(renews=[G1, G2, G3])]))
    refused = r.get('secret_exception_refusals') or []
    check(not r.get('secret_exceptions') and [x.get('code') for x in refused] == [LIMIT],
          'H2: a third renewal over the kit default cap of 2 was not refused as %s: %r / %r'
          % (LIMIT, r.get('secret_exceptions'), refused))

    # ---- H3: the cap ---------------------------------------------------------------------------------
    r = res(E.sx_central([sx(renews=[G1, G2])], numbers={'max_exception_renewals': 1}))
    check(not r.get('secret_exceptions') and LIMIT in [x.get('code') for x in r.get('secret_exception_refusals') or []],
          'H3: the register cap of 1 did not refuse a twice-renewed exception: %r' % r.get('secret_exception_refusals'))
    r = res(E.sx_central([sx(renews=[G1, G2, G3])], numbers={'max_exception_renewals': 5}))
    check(len(r.get('secret_exceptions') or []) == 1, 'H3: the register cap of 5 did not admit three renewals: %r'
          % r.get('secret_exception_refusals'))
    for bad in (6, -1, '2', True, 2.5):
        r = res(E.sx_central([sx()], numbers={'max_exception_renewals': bad}))
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'H3: cap %r accepted: %r' % (bad, r['state']))
    repo_doc = {'schema_version': 2, 'register_id': 'repo', 'numbers': {'max_exception_renewals': 0},
                'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'}, 'policies': []}
    r = res(None, repo_doc)
    check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'H3: a repository file set the renewal cap: %r' % r['state'])

    # ---- H4: an unreadable history -------------------------------------------------------------------
    for bad in ('SEC-1', [{'ticket': 'not-a-key', 'approver': 'A', 'from': '2026-01-01', 'expires': '2026-02-01'}],
                [dict(G1, approver='')], [dict(G1, extra='x')]):
        r = res(E.sx_central([sx(renews=bad)]))
        codes = [x.get('code') for x in r.get('secret_exception_refusals') or []]
        check(not r.get('secret_exceptions') and (codes == ['SECRET_EXCEPTION_UNATTRIBUTED']
                                                    or r['state'] == rl.REGISTRATION_UNAVAILABLE),
              'H4: an unreadable secret-exception history %r was not refused: %r %r' % (bad, r['state'], codes))

    # ---- H5: a policy decision softening -------------------------------------------------------------
    def da_soft(renews):
        dec = E.decision()
        if renews is not None:
            dec['renews'] = renews
        return E.central([{'id': 'da', 'scope': {'org': 'acme', 'environment_tier': 'prod'},
                           'deploy_approval': {'self_review_prevented': 'not_required'}, 'decision': dec}])
    r = res(da_soft([G1]))
    w = [x for x in r.get('weakenings') or [] if x.get('control') == 'deploy-approval']
    check(r['state'] == rl.POLICY_RESOLVED and len(w) == 1 and w[0].get('renewals') == 1
          and 'previously excepted 1 time(s) since 2026-01-10' in (w[0].get('history') or ''),
          'H5: a once-renewed softening is not a weakening row carrying its history: %r %r' % (r['state'], w))
    r = res(da_soft([G1, G2, G3]))
    check(r['state'] == LIMIT and r.get('routes_to') == 'DECISION_REQUIRED' and not r.get('weakenings')
          and r['deploy_approval']['prod']['self_review_prevented'] == 'required',
          'H5: a softening renewed over the cap was not refused (%r / %r / %r)'
          % (r['state'], r.get('routes_to'), r.get('weakenings')))
    r = res(da_soft('again'))
    check(r['state'] == 'POLICY_DECISION_UNATTRIBUTED', 'H4: an unreadable decision history resolved %r' % r['state'])

    # ---- H1 / H2 through the gate's own steps --------------------------------------------------------
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    steps = doc['jobs']['security-gate'].get('steps') or []
    work = tempfile.mkdtemp(prefix='exception-lifecycle-')
    try:
        for name, items, excepted, want in (
                ('first', [sx()], True, 'first exception'),
                ('renewed', [sx(renews=[G1, G2])], True, HISTORY_2),
                ('over_cap', [sx(renews=[G1, G2, G3])], False, LIMIT)):
            pol = E.policy_outputs(work, E.sx_central(items))
            g = E.run_job(bash, steps, pol, E.secret_seed([E.fp_a]))
            print('  gate %-9s secret_gate=%-8s route=%s' % (name, g['gate'].get('secret_gate'), g['route']))
            if excepted:
                check(g['gate'].get('secret_gate') == 'EXCEPTED', 'H1: gate %s: the exception was not applied' % name)
                check(want in g['gate_summary'], 'H1: gate %s: the summary does not show %r' % (name, want))
                check(want in (g['gate'].get('secret_exceptions_applied') or ''),
                      'H1: gate %s: secret_exceptions_applied (it feeds the run record) lacks %r: %r'
                      % (name, want, g['gate'].get('secret_exceptions_applied')))
            else:
                check(g['route'] == 'BLOCKED' and g['verdict_rc'] != 0, 'H2: gate %s: over the cap the secret did not '
                      'block: %r' % (name, g['route']))
                check(want in g['gate_summary'], 'H2: gate %s: the summary does not name %s' % (name, want))
        # The policy weakening's history reaches the gate's enforcement summary.
        pol = E.policy_outputs(work, da_soft([G1]))
        g = E.run_job(bash, steps, pol, E.scanners())
        check('previously excepted 1 time(s) since 2026-01-10' in g['summary'],
              'H5: the posture summary does not show the policy exception\'s history')
    except (OSError, subprocess.CalledProcessError) as exc:
        print('UNKNOWN: the fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # ---- H1 / H5: the run record ---------------------------------------------------------------------
    rec_step = next((s for s in steps if s.get('id') == 'record'), {})
    check('policy-exceptions' in (rec_step.get('with') or {}),
          'H5: the gate does not hand the policy exceptions to the run record')
    # The run-record composite's environment, one name per line (names of data, never states).
    env = dict(os.environ,
               ASSURANCE='FINDINGS',
               ENFORCEMENT='ADVISORY',
               SECRET_GATE='EXCEPTED',
               DISCOVERY='COMPLETE',
               SCANNER_STATES='{}',
               REPORT_RESULT='success',
               BLOCKING_FINDINGS='1',
               COMMIT_SHA='a' * 40,
               RUN_ID='1',
               REPOSITORY='acme/ledger-api',
               SECRET_EXCEPTIONS=json.dumps([{'finding': E.fp_a, 'ticket': 'SEC-1500', 'approver': 'Dana Example',
                                              'expires': '2099-01-31', 'entry': 'sx', 'renewals': 2,
                                              'history': HISTORY_2}]),
               POLICY_EXCEPTIONS=json.dumps([{'input': 'policy entry da', 'control': 'deploy-approval',
                                              'authority': 'Dana Example', 'expires': '2099-01-31',
                                              'exception_ref': 'SEC-9', 'renewals': 1, 'history': 'h1'},
                                             {'input': 'advisory_mode', 'control': 'security-gate'}]))
    tmp = tempfile.mkdtemp(prefix='run-record-')
    try:
        out = os.path.join(tmp, 'r.json')
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'run_record.py'), '--out', out],
                           capture_output=True, text=True, env=env)
        rec = json.load(io.open(out, encoding='utf-8')) if p.returncode == 0 and os.path.exists(out) else {}
        check(p.returncode == 0, 'H1: the run record with histories is invalid: %s' % (p.stdout + p.stderr)[-400:])
        if rec:
            jsonschema.validate(rec, json.load(io.open(os.path.join(ROOT, 'schemas', 'assurance-result.schema.json'),
                                                       encoding='utf-8')))
            sxr = rec.get('secret_exceptions') or [{}]
            check(sxr[0].get('history') == HISTORY_2 and sxr[0].get('renewals') == 2,
                  'H1: the run record does not carry the secret exception\'s history: %r' % sxr)
            pe = rec.get('policy_exceptions') or []
            check(len(pe) == 1 and pe[0].get('entry') == 'da' and pe[0].get('history') == 'h1'
                  and pe[0].get('renewals') == 1,
                  'H5: the run record does not list the policy exception with its history: %r' % pe)
    except (ValueError, jsonschema.ValidationError) as exc:
        fails.append('H1: the run record is not schema-valid: %s' % str(exc)[:300])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- H6: the deploy's version-gap exception ------------------------------------------------------
    valid = {'weakening_authority': 'A. Named Person', 'weakening_reason': 'no carried scanner reads it yet',
             'weakening_exception_ref': 'SEC-1600', 'weakening_expires': '2099-12-31'}
    cases = [
        ('within_cap', [G1, G2], '', True, HISTORY_2),
        ('first', [], '', True, 'first exception'),
        ('over_cap', [G1, G2, G3], '', False, LIMIT),
        ('lower_cap', [G1, G2], '1', False, LIMIT),
        ('higher_cap_not_honoured', [G1, G2, G3], '5', False, LIMIT),
        ('unreadable', 'not json', '', False, 'weakening_renews'),
    ]
    for wf in D.deploy_workflows:
        name = os.path.basename(wf)
        ddoc = D.load(wf)
        declared = D.inputs_of(ddoc)
        for i in ('weakening_renews', 'max_exception_renewals'):
            check(i in declared, 'H6: %s does not declare %s' % (name, i))
        _, step = D.step_named(ddoc, VERDICT_STEP)
        if step is None:
            fails.append('H6: %s has no verdict step' % name)
            continue
        for case, renews, cap, must, phrase in cases:
            values = {'inputs.routing_result': 'PROCEED_WITH_ADVISORY', 'inputs.environment_tier': 'prod',
                      'inputs.advisory_causes': 'VERSION_GAP', 'inputs.max_exception_renewals': cap,
                      'inputs.weakening_renews': renews if isinstance(renews, str) else
                      (json.dumps(renews) if renews else '')}
            values.update(('inputs.' + k, v) for k, v in valid.items())
            rc, out, log, summ = D.run_script(bash, step['run'], D.step_env(ddoc, step, values))
            print('  deploy %-32s %-24s exit=%d ruling=%s' % (name, case, rc, out.get('version_gap_ruling')))
            if must:
                check(rc == 0 and out.get('version_gap_ruling') == 'VERSION_GAP_EXCEPTION_ACCEPTED',
                      'H6: %s %s: refused an exception within the cap (exit %d)\n%s' % (name, case, rc, log[-400:]))
                check(phrase in (log + summ), 'H6: %s %s: the history %r is not shown' % (name, case, phrase))
            else:
                check(rc != 0 and out.get('version_gap_ruling') == 'VERSION_GAP_REFUSED',
                      'H6: %s %s: PROCEEDED (exit %d, ruling %r)' % (name, case, rc, out.get('version_gap_ruling')))
                check(phrase in log, 'H6: %s %s: refused without naming %r\n%s' % (name, case, phrase, log[-400:]))

    # ---- H7: --validate and the taxonomy -------------------------------------------------------------
    tmp = tempfile.mkdtemp(prefix='exception-validate-')
    try:
        path = os.path.join(tmp, 'c.json')
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(E.sx_central([sx(renews=[G1, G2, G3])])))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'), '--validate',
                            path, '--today', TODAY], capture_output=True, text=True)
        check(p.returncode == 1 and LIMIT in p.stdout, 'H7: --validate did not name %s: %s' % (LIMIT, p.stdout[-300:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    tax = yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
    found = [ns for ns, body in (tax.get('namespaces') or {}).items() if LIMIT in ((body or {}).get('values') or {})]
    check(found, 'H7: %s is not registered in assurance-taxonomy.yaml' % LIMIT)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: every exception shows its history ("first exception", or "previously excepted N time(s) since '
          '<date>, tickets ..., approvers ...") in the resolver, the gate summary, the gate output and the run '
          'record; renewals over the cap (register numbers.max_exception_renewals, kit default 2, 0..5, central '
          'only) are refused as EXCEPTION_RENEWAL_LIMIT and the finding reverts -- a secret blocks, a softening '
          'reverts, a version-gap deploy is refused; an unreadable history is unattributed, never "none".')
    return 0


if __name__ == '__main__':
    sys.exit(main())
