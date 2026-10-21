#!/usr/bin/env python3
"""environment_tier and team_pattern change ENFORCEMENT, never scanner truth. (ledger L33)

WHY THIS EXISTS (AXES_AND_PHASES.md enforcement tables; ETFB sections 3, 4.0, 4.3 item 4, 8.6)

    No input for either axis existed anywhere in the kit. Both arrive through the registration
    file (L32) and are consumed by these pure functions, which this proves over fixtures:

      1  PRODUCTION TIERS STOP ON EVIDENCE_UNTRUSTED. uat and prod are both production; "scanner
         did not run" blocks there. sandbox, dev and test warn instead -- the declared position.
      2  A CONTROL WHOSE FLOOR IS BLOCKED STOPS WHEN UNTRUSTED AT EVERY TIER. A secret scanner
         that could not run is not a clean secret scan at dev either.
      3  A TIER MAY ONLY RAISE A FLOOR, NEVER LOWER IT. Whatever the tier, the per-control
         minimum handed back is at least the rung's.
      4  TEAM SIZE CHANGES THE MECHANISM, NEVER THE FLOOR. solo_dev makes a required second
         reviewer UNSATISFIABLE, not waived: every human control is an unvalidated human-workflow
         path, reported as such and never as passing. pair_devs records no separation of duties on
         an exception. full_team has every control available.
      5  THE BREACH AUTHORITY FOLLOWS THE TEAM PATTERN (ETFB 8.6). solo_dev escalates outside the
         repository; nothing in a solo repository can approve its own breached CRITICAL.
      6  NEITHER AXIS KNOWS A SCANNER. The functions take a tier or a pattern and return
         enforcement facts only; an unregistered value refuses rather than mapping to a neighbour.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        import enforcement_axes as ax
    except ImportError as exc:
        print('FAIL: no enforcement axes exist (%s). AXES_AND_PHASES.md names environment_tier and '
              'team_pattern as inputs to enforcement and nothing in the kit consumes either.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # 1  Tiers.
    for tier in ('uat', 'prod'):
        b = ax.tier_behaviour(tier)
        check(b['production'] is True and b['stops_on_evidence_untrusted'] is True,
              '%s is a production tier and must stop on EVIDENCE_UNTRUSTED: %r' % (tier, b))
    for tier in ('sandbox', 'dev', 'test'):
        b = ax.tier_behaviour(tier)
        check(b['production'] is False and b['stops_on_evidence_untrusted'] is False,
              '%s is not production and must warn on EVIDENCE_UNTRUSTED: %r' % (tier, b))
        # 2  ... except a BLOCKED-floor control.
        check(b['blocked_floor_stops_when_untrusted'] is True,
              '%s let a BLOCKED-floor control through when its evidence was untrusted' % tier)
    check(ax.gate_stops('EVIDENCE_UNTRUSTED', 'dev', floor_of_control='PROCEED_WITH_ADVISORY') is False,
          'dev stopped on an untrusted advisory control')
    check(ax.gate_stops('EVIDENCE_UNTRUSTED', 'dev', floor_of_control='BLOCKED') is True,
          'dev did not stop on an untrusted BLOCKED-floor control (secrets)')
    check(ax.gate_stops('EVIDENCE_UNTRUSTED', 'prod', floor_of_control='PROCEED_WITH_ADVISORY') is True,
          'prod did not stop on EVIDENCE_UNTRUSTED')
    check(ax.gate_stops('BLOCKED', 'sandbox', floor_of_control='PROCEED') is True,
          'BLOCKED did not stop at sandbox; a block is a block at every tier')
    check(ax.gate_stops('DECISION_REQUIRED', 'prod', floor_of_control='BLOCKED') is False,
          'DECISION_REQUIRED stopped the gate; it is a decision owed, not a refusal')
    try:
        ax.tier_behaviour('staging')
        check(False, 'an unregistered tier mapped to a neighbour instead of refusing')
    except ValueError:
        pass

    # 3  A tier only raises a floor.
    floor = {'secrets': 'BLOCKED', 'new_critical_high': 'PROCEED_WITH_ADVISORY', 'other_findings': 'PROCEED_WITH_ADVISORY'}
    for tier in ('sandbox', 'dev', 'test', 'uat', 'prod'):
        raised = ax.apply_tier(floor, tier)
        for control, base in floor.items():
            check(ax.precedence_max(base, raised[control]) == raised[control],
                  'tier %s LOWERED %s from %s to %s' % (tier, control, base, raised[control]))
        check(set(raised) == set(floor), 'tier %s added or removed a control' % tier)

    # 4  Team patterns.
    hc = ax.human_controls('solo_dev')
    check(all(v == ax.HUMAN_CONTROL_UNVALIDATED for v in hc.values()) and hc,
          'solo_dev did not report every human control as an unvalidated path: %r' % hc)
    check(ax.unvalidated_paths('solo_dev') == sorted(hc), 'solo_dev unvalidated paths not enumerated')
    hc = ax.human_controls('pair_devs')
    check(hc['approval_separation'] == ax.HUMAN_CONTROL_NO_SEPARATION and hc['second_reviewer'] == ax.HUMAN_CONTROL_AVAILABLE,
          'pair_devs: mutual review is available and separation is not: %r' % hc)
    hc = ax.human_controls('full_team')
    check(all(v == ax.HUMAN_CONTROL_AVAILABLE for v in hc.values()), 'full_team lacks a control: %r' % hc)
    check(ax.unvalidated_paths('full_team') == [], 'full_team reported an unvalidated path')
    check(ax.human_controls('small_team')['security_reviewer_distinct'] == ax.HUMAN_CONTROL_UNVALIDATED,
          'small_team claimed a security reviewer distinct from author and approver (that is 5+)')
    try:
        ax.human_controls('committee')
        check(False, 'an unregistered team_pattern mapped to a neighbour instead of refusing')
    except ValueError:
        pass
    # The floor is untouched by team size: the axes expose nothing that returns a routing result
    # from a team pattern.
    check(not hasattr(ax, 'team_floor') and not hasattr(ax, 'apply_team'),
          'the team axis exposes a floor function; team size must never touch a floor')

    # 5  Breach authority.
    check(ax.breach_authority('solo_dev')['escalates_outside_repository'] is True,
          'solo_dev breach decisions stayed inside the repository')
    for p in ('pair_devs', 'small_team', 'full_team'):
        check(ax.breach_authority(p)['escalates_outside_repository'] is False, '%s escalated outside' % p)
    check(ax.breach_authority('pair_devs')['separation'] == ax.HUMAN_CONTROL_NO_SEPARATION,
          'pair_devs breach authority did not record the missing separation')

    # 6  Nothing here names a scanner, a language, a path or a depth.
    for name in dir(ax):
        low = name.lower()
        check(not any(w in low for w in ('scanner', 'language', 'depth', 'scan_path', 'codeql', 'semgrep',
                                         'applicab')),
              'the enforcement axes expose %r: an axis contaminated by applicability or depth' % name)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: production tiers stop on EVIDENCE_UNTRUSTED and lower tiers warn, except where the '
          'floor is BLOCKED; a tier only raises a floor; solo_dev reports every human control as an '
          'unvalidated path and lowers nothing; pair_devs records no separation; the breach authority '
          'follows the team pattern and solo_dev escalates outside the repository; neither axis knows '
          'a scanner; unregistered values refuse.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
