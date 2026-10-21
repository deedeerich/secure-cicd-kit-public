#!/usr/bin/env python3
"""The rung ladder: a floor per control that cherry-picks may only raise, and a derived policy_mode.

WHY THIS EXISTS (ledger L32; ETFB sections 1-4, 10, 13; SINGLE_PIPELINE_TARGET.md stage 1, 8.3)

    ETFB section 13 settled that `policy_mode` is DERIVED from the rung and owed "the derivation
    table itself, and the check that fails a run in which policy_mode was supplied rather than
    computed". This proves both, as pure functions over fixtures, plus the floor invariant that
    makes a rung a rung rather than a menu:

      1  THE LADDER IS ETFB 1.1. Every (control class, rung) cell is the table's value.
      2  MONOTONE. For every control, run >= walk >= crawl. A non-monotone ladder is a menu.
      3  SECRETS BLOCK AT EVERY RUNG, and no cherry-pick can say otherwise.
      4  A CHERRY-PICK MAY ONLY STRENGTHEN. One below the floor is a POLICY DEFECT, named -- not
         applied-then-overridden, not silently dropped. (The adversarial case.)
      5  policy_mode IS COMPUTED, NEVER SUPPLIED. A run that received one refuses by name, whatever
         the value -- even the value the derivation would have produced. (The adversarial case.)
      6  CELLS ARE MONOTONE ALONG THE PROMOTION PATH, and uat equals prod. A cell that violates it
         is a policy defect.
      7  A PULL REQUEST IS EVALUATED AT THE RUNG OF THE HIGHEST ENVIRONMENT ITS MERGE CAN REACH
         without a further human gate.
      8  THE DECLARATION NAMES THE TARGET; THE EVIDENCE SETS THE EFFECTIVE. A declared `run` with
         no promotion evidence is effective `crawl`, the record carries both, and the gate obeys
         the effective one.
      9  DECLARING DOWNWARD IS A WEAKENING EVENT: a demotion needs a reason, an authority and an
         expiry, or it is WEAKENING_UNATTRIBUTED and routes DECISION_REQUIRED.
     10  EVERY NUMBER COMES FROM CONFIGURATION. The consecutive-run count for promotion is read
         from the numbers handed in; a missing number refuses rather than defaulting.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

NUMBERS = {'promotion_consecutive_clean_runs': 5}


def main():
    try:
        import rung_ladder as rl
    except ImportError as exc:
        print('FAIL: no rung ladder exists (%s). ETFB sections 1-4 are designed and not built: '
              'nothing derives a floor from a rung, and nothing can refuse a supplied policy_mode.'
              % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # 1  The ladder is ETFB section 1.1, cell by cell.
    expected = {
        'secrets':                   ('BLOCKED', 'BLOCKED', 'BLOCKED'),
        'new_critical_high':         ('PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'BLOCKED'),
        'pre_existing_on_track':     ('PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'PROCEED_WITH_ADVISORY'),
        'pre_existing_track_lapsed': ('PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'BLOCKED'),
        'other_findings':            ('PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'DECISION_REQUIRED'),
    }
    for control, (c, w, r) in expected.items():
        for rung, want in zip(('crawl', 'walk', 'run'), (c, w, r)):
            got = rl.rung_floor(rung).get(control)
            check(got == want, 'ladder cell (%s, %s) is %r, ETFB 1.1 says %s' % (control, rung, got, want))
    check(rl.derive_policy_mode('crawl') == 'adoption' and rl.derive_policy_mode('run') == 'strict',
          'policy_mode derivation disagrees with ETFB 13: crawl -> adoption, run -> strict')
    try:
        rl.derive_policy_mode('sprint')
        check(False, 'an unregistered rung derived a policy_mode instead of refusing')
    except ValueError:
        pass

    # 2  Monotone: run >= walk >= crawl for every control -- except the ONE row ETFB 1.1 itself
    #    writes non-monotone (pre-existing on an unexpired track: DECISION_REQUIRED at walk,
    #    PROCEED_WITH_ADVISORY at run, "a schedule, not amnesty"). The table is kept verbatim and
    #    the exemption must be NAMED in the module, so a reader sees it rather than a check that
    #    was quietly loosened. An owner decision is recorded in the lane report.
    check(rl.monotone_exempt == ('pre_existing_on_track',),
          'the non-monotone row is not named exactly: %r' % (rl.monotone_exempt,))
    for control in rl.control_classes:
        c, w, r = (rl.rung_floor(x)[control] for x in ('crawl', 'walk', 'run'))
        monotone = rl.precedence_max(c, w) == w and rl.precedence_max(w, r) == r
        if control in rl.monotone_exempt:
            check(not monotone, '%s is listed as exempt but IS monotone; the exemption is stale' % control)
        else:
            check(monotone, 'ladder is not monotone on %s: crawl=%s walk=%s run=%s -- a non-monotone '
                            'ladder is a menu' % (control, c, w, r))

    # 3  Secrets: BLOCKED at every rung, and a cherry-pick cannot lower it.
    r = rl.effective_minimum('crawl', [{'control': 'secrets', 'minimum': 'PROCEED_WITH_ADVISORY',
                                        'reason': 'x', 'authority': 'y'}])
    check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR and r['effective']['secrets'] == 'BLOCKED',
          'a cherry-pick softened secrets at crawl: %r' % r)

    # 4  Cherry-picks strengthen only. Equal is a no-op; above is applied; below is a DEFECT.
    r = rl.effective_minimum('walk', [{'control': 'deps-scan', 'minimum': 'BLOCKED',
                                       'reason': 'supply chain is the exposure', 'authority': 'security-lead'}])
    check(r['state'] == rl.POLICY_RESOLVED and r['effective'].get('deps-scan') == 'BLOCKED',
          'a strengthening cherry-pick was not applied: %r' % r)
    check(r['effective']['new_critical_high'] == 'DECISION_REQUIRED',
          'a cherry-pick on one control changed another control\'s floor')
    # THE ATTACK: a cherry-pick that weakens, at run. The floor for other findings at run is
    # DECISION_REQUIRED; asking for PROCEED_WITH_ADVISORY is `run` wearing crawl's label.
    r = rl.effective_minimum('run', [{'control': 'iac-scan', 'minimum': 'PROCEED_WITH_ADVISORY',
                                      'reason': 'noisy', 'authority': 'repo-owner'}])
    check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR,
          'a cherry-pick BELOW the floor was not refused by name: state=%r' % r['state'])
    check(r['effective'].get('iac-scan', r['effective']['other_findings']) == 'DECISION_REQUIRED',
          'the below-floor pick was applied (silently overridden later is not refusal)')
    check(any('iac-scan' in d for d in r['defects']), 'the defect does not name the control')
    # The same pick at crawl: it is a strengthening there and is applied.
    r = rl.effective_minimum('crawl', [{'control': 'iac-scan', 'minimum': 'DECISION_REQUIRED',
                                        'reason': 'x', 'authority': 'y'}])
    check(r['state'] == rl.POLICY_RESOLVED and r['effective']['iac-scan'] == 'DECISION_REQUIRED',
          'a strengthening pick at crawl was refused: %r' % r)
    # An unregistered routing result in a pick is refused, not compared.
    r = rl.effective_minimum('run', [{'control': 'deps-scan', 'minimum': 'hard-block', 'reason': 'x',
                                      'authority': 'y'}])
    check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR or r['defects'],
          'a cherry-pick with an unregistered minimum was accepted')
    # The record emits the registered rung, the effective set and every divergence (ETFB 2.2).
    r = rl.effective_minimum('walk', [{'control': 'deps-scan', 'minimum': 'BLOCKED', 'reason': 'x',
                                       'authority': 'y'}])
    check(r['rung'] == 'walk' and 'divergences' in r and any(
        d.get('control') == 'deps-scan' for d in r['divergences']),
        'the effective set does not emit the divergence from the rung floor: %r' % r)

    # 5  policy_mode must be computed, never supplied -- even when the supplied value is "right".
    for supplied in ('strict', 'adoption', '', 'anything'):
        r = rl.refuse_supplied_policy_mode({'policy_mode': supplied})
        check(r['state'] == rl.POLICY_MODE_SUPPLIED,
              'policy_mode=%r was SUPPLIED and the run was not refused (state %r)' % (supplied, r['state']))
    r = rl.refuse_supplied_policy_mode({'language': 'python'})
    check(r['state'] == rl.POLICY_RESOLVED, 'a run with no policy_mode input was refused')
    # Spelling variants are supplied too: a near-miss is not a different input.
    for key in ('Policy-Mode', 'policy-mode', 'policyMode'):
        r = rl.refuse_supplied_policy_mode({key: 'strict'})
        check(r['state'] == rl.POLICY_MODE_SUPPLIED, 'policy_mode supplied as %r slipped through' % key)

    # 6  Cells monotone along the promotion path; uat == prod.
    cells = {'dev': {'tier': 'dev', 'rung': 'crawl'}, 'uat': {'tier': 'uat', 'rung': 'run'},
             'prod': {'tier': 'prod', 'rung': 'run'}}
    check(rl.check_cells_monotone(cells) == [], 'a monotone cell set was reported as a defect')
    bad = {'dev': {'tier': 'dev', 'rung': 'run'}, 'prod': {'tier': 'prod', 'rung': 'crawl'}}
    check(rl.check_cells_monotone(bad), 'rung(dev)=run above rung(prod)=crawl was accepted')
    bad = {'uat': {'tier': 'uat', 'rung': 'walk'}, 'prod': {'tier': 'prod', 'rung': 'run'}}
    check(rl.check_cells_monotone(bad), 'uat != prod was accepted; both are production tiers')

    # 7  A pull request is evaluated at the highest environment reachable without a human gate.
    cells = {'dev': {'tier': 'dev', 'rung': 'crawl', 'reachable_from_merge_without_human_gate': True},
             'prod': {'tier': 'prod', 'rung': 'run', 'reachable_from_merge_without_human_gate': True}}
    check(rl.rung_for_pull_request(cells) == ('prod', 'run'),
          'a PR whose merge auto-deploys to prod was not evaluated at prod\'s rung')
    cells['prod']['reachable_from_merge_without_human_gate'] = False
    check(rl.rung_for_pull_request(cells) == ('dev', 'crawl'),
          'a PR gated by a human before prod was evaluated at prod\'s rung')
    check(rl.rung_for_pull_request({}) == (None, None), 'no reachable cell produced a rung')

    # 8  Declared is the target; evidence sets the effective. The record carries both.
    cell = {'rung': 'run', 'promotion_evidence': {}}
    r = rl.effective_rung(cell, NUMBERS)
    check(r['declared'] == 'run' and r['effective'] == 'crawl',
          'a declared run with no evidence was not effective crawl: %r' % r)
    check(r['state'] == rl.RUNG_EFFECTIVE_BELOW_DECLARED and r['missing'],
          'the divergence was not named with the missing evidence: %r' % r)
    walk_ev = {'controls_executed_at_baseline': {'consecutive_clean_runs': 5, 'evidence_ref': 'runs/1-5'},
               'ledger_populated_and_owned': 'ledger@abc', 'entries_classified': 'ledger@abc',
               'human_controls_assessed': 'review/7'}
    r = rl.effective_rung({'rung': 'run', 'promotion_evidence': {'walk': walk_ev}}, NUMBERS)
    check(r['effective'] == 'walk', 'walk evidence alone made the cell effective %r' % r['effective'])
    run_ev = {'baseline_forced_failure_demonstrated': 'prove_baseline_cascade run 9',
              'track_closure_verified': 'ledger@def entry 3', 'day_one_fix_availability_established': 'ledger@def'}
    r = rl.effective_rung({'rung': 'run', 'promotion_evidence': {'walk': walk_ev, 'run': run_ev}}, NUMBERS)
    check(r['effective'] == 'run' and r['state'] == rl.POLICY_RESOLVED,
          'full evidence did not make the cell effective run: %r' % r)
    # Configuration is not evidence: fewer consecutive runs than the configured number is not walk.
    short = dict(walk_ev, controls_executed_at_baseline={'consecutive_clean_runs': 4, 'evidence_ref': 'r'})
    r = rl.effective_rung({'rung': 'walk', 'promotion_evidence': {'walk': short}}, NUMBERS)
    check(r['effective'] == 'crawl', '4 of 5 configured consecutive runs was accepted as walk evidence')
    # 10  The number is read from configuration; a missing number refuses, it does not default.
    r = rl.effective_rung({'rung': 'walk', 'promotion_evidence': {'walk': walk_ev}}, {})
    check(r['state'] == rl.POLICY_NUMBER_NOT_CONFIGURED,
          'a missing consecutive-run number defaulted instead of refusing: %r' % r)

    # 9  Demotion is a weakening event with attribution and an expiry.
    hist = [{'from': 'run', 'to': 'walk', 'reason': 'incident freeze', 'authority': 'security-lead',
             'expires': '2099-01-01', 'date': '2026-10-01'}]
    r = rl.demotion_record(hist, today='2026-10-14')
    check(r and r[0]['class'] == 'GATE_SOFTENED' and r[0]['state'] == 'WEAKENING_IN_FORCE'
          and r[0]['attribution'] == 'WEAKENING_ATTRIBUTED', 'an attributed demotion misrecorded: %r' % r)
    r = rl.demotion_record([{'from': 'run', 'to': 'walk', 'date': '2026-10-01'}], today='2026-10-14')
    check(r[0]['attribution'] == 'WEAKENING_UNATTRIBUTED' and r[0]['routes_to'] == 'DECISION_REQUIRED',
          'a demotion with no reason or authority did not route DECISION_REQUIRED: %r' % r)
    r = rl.demotion_record([dict(hist[0], expires='2026-01-01')], today='2026-10-14')
    check(r[0]['attribution'] == 'WEAKENING_EXCEPTION_EXPIRED', 'an expired demotion read as in force')
    r = rl.demotion_record([dict(hist[0], expires='never')], today='2026-10-14')
    check(r[0]['attribution'] == 'WEAKENING_EXCEPTION_EXPIRED', 'an unreadable expiry read as unexpired')
    r = rl.demotion_record([{'from': 'walk', 'to': 'run', 'date': '2026-10-01'}], today='2026-10-14')
    check(r == [], 'a promotion was recorded as a weakening')

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the ladder is ETFB 1.1 cell for cell and monotone; secrets block at every rung; a '
          'cherry-pick strengthens or is a named policy defect; a supplied policy_mode is refused '
          'whatever its value; cells are monotone with uat == prod; a PR is evaluated at the highest '
          'reachable environment; the effective rung follows the evidence and the record carries '
          'both; a demotion is an attributed weakening or owes a decision; a missing number refuses.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
