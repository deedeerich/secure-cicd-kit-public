#!/usr/bin/env python3
"""The deploy reusables emit a control-posture record, and it routes what the deploy actually did.

WHY THIS EXISTS (ledger L31 for the deploy surface; tests/check_weakening_record.py EXEMPT entries)

    Both deploy reusables declared weakening inputs -- rollback_on_failure, swap_on_healthy,
    health_retries, health_interval_seconds, health_path, slot -- and recorded none of them. A
    caller who switched reversal off, or staged into a slot and never swapped, was reported
    exactly like one who deployed at baseline. The exemption that accounted for that expired
    2026-10-31 and is deleted with this proof: the deploy workflows now carry the same posture
    step the other three reusables emit (W1-W7), and the record ROUTES what the job did.

WHAT IS RUN
    The `posture` step of each deploy reusable, extracted as shipped, under bash, with the
    outcomes of the verdict, tier, capability and report steps stubbed as the runner renders them.

CASES (docs/PROOF_RULE.md)
    allowed           baseline inputs, every control succeeded, DEPLOY_HEALTHY      -> PROCEED
    attack            rollback_on_failure false at tier prod: the capability step already REFUSED
                      (UNAVAILABLE at a production tier), the report says DEPLOY_REFUSED
                                                                                  -> BLOCKED, never
                      DECISION_REQUIRED or PROCEED_WITH_ADVISORY: the refusal outranks the record
    weakening         rollback_on_failure false at tier dev, healthy, unattributed  -> DECISION_REQUIRED
                      ... attributed (reason + authority)                            -> PROCEED_WITH_ADVISORY
                      and `reversal` is in controls_skipped either way
    missing-evidence  the report says STATUS_UNTRUSTED / PARTIAL_APPLY               -> EVIDENCE_UNTRUSTED
                      the upstream verdict refused with EVIDENCE_UNTRUSTED           -> EVIDENCE_UNTRUSTED
    recovery          the upstream verdict refused with BLOCKED                      -> BLOCKED
                      health failed and the reversal ran: ROLLBACK_VERIFIED          -> BLOCKED
    static            all nine rows emitted (W5 holds the shape; this reads the values), and the
                      posture step comes after the report step so it can read the outcome

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402

ROWS = ('routing_result', 'controls_required', 'controls_executed', 'controls_unavailable',
        'controls_reduced', 'controls_skipped', 'weakenings', 'weakening_attribution',
        'weakening_record')


def base_inputs(wf):
    i = {'inputs.routing_result': 'PROCEED', 'inputs.environment_tier': 'dev',
         'inputs.health_path': '/health', 'inputs.rollback_on_failure': 'true',
         'inputs.weakening_reason': '', 'inputs.weakening_authority': '',
         'inputs.weakening_exception_ref': '', 'inputs.weakening_expires': ''}
    if wf == D.APPSERVICE:
        i.update({'inputs.slot': 'staging', 'inputs.swap_on_healthy': 'true',
                  'inputs.health_retries': '18', 'inputs.health_interval_seconds': '10'})
    else:
        i.update({'inputs.health_retries': '12', 'inputs.health_interval_seconds': '10'})
    return i


def outcomes(verdict='success', tier='success', capability='success', cap_value='AVAILABLE',
             report='success', deployment='DEPLOY_HEALTHY', job='success',
             ruling='VERSION_GAP_NOT_ENGAGED'):
    # The verdict step answers on every path it reaches (KDEC-014); an empty ruling is an absent
    # answer, proven in tests/prove_version_gap_production.py.
    return {'steps.verdict.outcome': verdict, 'steps.verdict.outputs.version_gap_ruling': ruling,
            'steps.tier.outcome': tier,
            'steps.capability.outcome': capability,
            'steps.capability.outputs.rollback_capability': cap_value,
            'steps.report.outcome': report,
            'steps.report.outputs.deployment_outcome': deployment, 'job.status': job}


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = D.bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    bad = []
    for wf in D.deploy_workflows:
        name = os.path.basename(wf)
        doc = D.load(wf)
        steps = D.steps(doc)
        pos = [i for i, s in enumerate(steps) if s.get('id') == 'posture']
        rep = [i for i, s in enumerate(steps) if s.get('name') == 'Reconcile and report outcome']
        if not pos:
            bad.append('%s: no step with id posture -- the deploy records no control posture' % name)
            continue
        if rep and pos[0] < rep[0]:
            bad.append('%s: the posture step runs before the report, so it cannot read the outcome'
                       % name)
        step = steps[pos[0]]
        if 'always()' not in str(step.get('if', '')):
            bad.append('%s: the posture step is not `if: always()`; a refused deploy would record '
                       'nothing' % name)
        base = base_inputs(wf)
        unattributed = dict(base, **{'inputs.rollback_on_failure': 'false'})
        attributed = dict(unattributed, **{'inputs.weakening_reason': 'canary target',
                                           'inputs.weakening_authority': 'platform lead'})
        cases = [
            ('allowed', base, outcomes(), 'PROCEED'),
            ('attack-refused-prod', dict(unattributed, **{'inputs.environment_tier': 'prod'}),
             outcomes(capability='failure', cap_value='UNAVAILABLE', report='failure',
                      deployment='DEPLOY_REFUSED', job='failure'), 'BLOCKED'),
            ('weakening-unattributed', unattributed, outcomes(cap_value='UNAVAILABLE'),
             'DECISION_REQUIRED'),
            ('weakening-attributed', attributed, outcomes(cap_value='UNAVAILABLE'),
             'PROCEED_WITH_ADVISORY'),
            ('missing-status-untrusted', base,
             outcomes(report='failure', deployment='STATUS_UNTRUSTED', job='failure'),
             'EVIDENCE_UNTRUSTED'),
            ('missing-partial-apply', base,
             outcomes(report='failure', deployment='PARTIAL_APPLY', job='failure'),
             'EVIDENCE_UNTRUSTED'),
            ('missing-upstream-untrusted', dict(base, **{'inputs.routing_result': 'EVIDENCE_UNTRUSTED'}),
             outcomes(verdict='failure', tier='skipped', capability='skipped', cap_value='',
                      report='failure', deployment='DEPLOY_REFUSED', job='failure'),
             'EVIDENCE_UNTRUSTED'),
            ('recovery-upstream-blocked', dict(base, **{'inputs.routing_result': 'BLOCKED'}),
             outcomes(verdict='failure', tier='skipped', capability='skipped', cap_value='',
                      report='failure', deployment='DEPLOY_REFUSED', job='failure'), 'BLOCKED'),
            ('recovery-rolled-back', base,
             outcomes(report='failure', deployment='ROLLBACK_VERIFIED', job='failure'), 'BLOCKED'),
        ]
        for case, inputs, outs, want in cases:
            values = dict(inputs, **outs)
            env = D.step_env(doc, step, values)
            rc, out, log, _summary = D.run_script(bash, step.get('run') or '', env)
            got = out.get('routing_result')
            print('  %-32s %-27s routing_result=%s' % (name, case, got))
            if rc != 0:
                bad.append('%s/%s: the posture step exited %d\n%s' % (name, case, rc, log[-400:]))
            if got != want:
                bad.append('%s/%s: routing_result=%r, want %s\n%s' % (name, case, got, want, log[-300:]))
            missing = [r for r in ROWS if r not in out]
            if missing:
                bad.append('%s/%s: rows not emitted: %s' % (name, case, missing))
            if case.startswith('weakening') and 'reversal' not in out.get('controls_skipped', ''):
                bad.append('%s/%s: reversal switched off is not in controls_skipped (%r)'
                           % (name, case, out.get('controls_skipped')))
            if case == 'allowed' and out.get('weakening_attribution') != 'WEAKENING_AT_BASELINE':
                bad.append('%s/allowed: attribution %r at baseline' % (name, out.get('weakening_attribution')))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: both deploy reusables emit the nine-row posture record; a refusal before the point '
          'of no return routes BLOCKED over any weakening; a weakening at a lower tier owes a decision '
          'until attributed; an untrusted or partial outcome routes EVIDENCE_UNTRUSTED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
