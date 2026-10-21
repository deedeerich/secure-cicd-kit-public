#!/usr/bin/env python3
"""The two ENFORCEMENT axes that are not the rung: environment_tier and team_pattern. (L33)

    AXES_AND_PHASES.md: "Environment and team decide ENFORCEMENT." Both are read downstream of the
    rung (ETFB section 4.0), both arrive through the registration file (scripts/policy_registration.py),
    and neither may touch scanner truth: nothing here takes or returns a scanner, a language, a
    path or a depth, and tests/prove_enforcement_axes.py checks the module's own surface for it.

ENVIRONMENT TIER (ETFB section 3; AXES_AND_PHASES.md; environment_tier in the taxonomy)

    may only RAISE a floor, never lower it. Its effect on the gate is one fact: at a production
    tier (uat, prod) EVIDENCE_UNTRUSTED stops the run; at sandbox, dev and test it warns -- the
    declared position, and exactly why uat and prod are both production. One exception at every
    tier: a control whose effective minimum is BLOCKED stops when its evidence is untrusted
    (secrets are the standing case: a secret scanner that could not run is not a clean secret scan
    at dev either).

    The AXES_AND_PHASES.md table's "new critical/high: block at test and above" is NOT applied here
    as a tier floor. ETFB (later, and the document that introduced the rung) places what blocks
    under the rung registered per cell, and a tier floor that blocked new critical/high at test
    would make `crawl` unregisterable at test -- a contradiction with "the rung is the business's
    declared posture". Whether the tier table should raise floors beyond the untrusted-evidence
    rule is an owner decision named in the lane report; until then apply_tier raises nothing and
    says so, rather than quietly deciding either way.

TEAM PATTERN (ETFB sections 4.0, 4.3 item 4, 8.6; team_pattern in the taxonomy)

    changes HOW a floor is satisfied, never WHETHER. solo_dev makes a required second reviewer
    UNSATISFIABLE, not waived -- every human control is an UNVALIDATED HUMAN-WORKFLOW PATH,
    reported as such and never as passing (human_control_availability in the taxonomy). The
    breach authority of section 8.6 follows the pattern; a solo repository escalates outside
    itself.

USAGE
    from enforcement_axes import tier_behaviour, gate_stops, apply_tier, human_controls, breach_authority
    python3 enforcement_axes.py --self-test
"""
import sys

PRECEDENCE = ('PROCEED', 'PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'EVIDENCE_UNTRUSTED', 'BLOCKED')
tier_order = ('sandbox', 'dev', 'test', 'uat', 'prod')
PRODUCTION_TIERS = ('uat', 'prod')
TEAM_PATTERNS = ('solo_dev', 'pair_devs', 'small_team', 'full_team')

# human_control_availability (assurance-taxonomy.yaml)
HUMAN_CONTROL_AVAILABLE = 'HUMAN_CONTROL_AVAILABLE'
HUMAN_CONTROL_UNVALIDATED = 'HUMAN_CONTROL_UNVALIDATED'
HUMAN_CONTROL_NO_SEPARATION = 'HUMAN_CONTROL_NO_SEPARATION'
HUMAN_CONTROLS = ('second_reviewer', 'approval_separation', 'codeowners_routing', 'security_reviewer_distinct')

# AXES_AND_PHASES.md "enforcement by team pattern", row for row.
HUMAN_CONTROL_TABLE = {
    'solo_dev':   {'second_reviewer': HUMAN_CONTROL_UNVALIDATED, 'approval_separation': HUMAN_CONTROL_UNVALIDATED,
                   'codeowners_routing': HUMAN_CONTROL_UNVALIDATED, 'security_reviewer_distinct': HUMAN_CONTROL_UNVALIDATED},
    'pair_devs':  {'second_reviewer': HUMAN_CONTROL_AVAILABLE, 'approval_separation': HUMAN_CONTROL_NO_SEPARATION,
                   'codeowners_routing': HUMAN_CONTROL_NO_SEPARATION, 'security_reviewer_distinct': HUMAN_CONTROL_UNVALIDATED},
    'small_team': {'second_reviewer': HUMAN_CONTROL_AVAILABLE, 'approval_separation': HUMAN_CONTROL_AVAILABLE,
                   'codeowners_routing': HUMAN_CONTROL_AVAILABLE, 'security_reviewer_distinct': HUMAN_CONTROL_UNVALIDATED},
    'full_team':  {'second_reviewer': HUMAN_CONTROL_AVAILABLE, 'approval_separation': HUMAN_CONTROL_AVAILABLE,
                   'codeowners_routing': HUMAN_CONTROL_AVAILABLE, 'security_reviewer_distinct': HUMAN_CONTROL_AVAILABLE},
}

# ETFB section 8.6: who decides at breach.
BREACH_AUTHORITY = {
    'full_team':  {'decider': 'a security reviewer distinct from author and approver',
                   'separation': HUMAN_CONTROL_AVAILABLE, 'escalates_outside_repository': False},
    'small_team': {'decider': 'CODEOWNERS routing; a reviewer who is not the author',
                   'separation': HUMAN_CONTROL_AVAILABLE, 'escalates_outside_repository': False},
    'pair_devs':  {'decider': 'mutual review; no separation of duties on an exception, recorded as such',
                   'separation': HUMAN_CONTROL_NO_SEPARATION, 'escalates_outside_repository': False},
    'solo_dev':   {'decider': 'an org-level authority outside the repository; the repository records an '
                              'unvalidated human-workflow path',
                   'separation': HUMAN_CONTROL_UNVALIDATED, 'escalates_outside_repository': True},
}


def precedence_max(*results):
    best = -1
    for r in results:
        if r not in PRECEDENCE:
            raise ValueError('%r is not a registered routing_result' % (r,))
        best = max(best, PRECEDENCE.index(r))
    return PRECEDENCE[best]


def _tier(tier):
    if tier not in tier_order:
        raise ValueError('%r is not a registered environment_tier (%s)' % (tier, ' | '.join(tier_order)))
    return tier


def _pattern(team_pattern):
    if team_pattern not in TEAM_PATTERNS:
        raise ValueError('%r is not a registered team_pattern (%s)' % (team_pattern, ' | '.join(TEAM_PATTERNS)))
    return team_pattern


def tier_behaviour(tier):
    """-> {tier, production, stops_on_evidence_untrusted, blocked_floor_stops_when_untrusted}."""
    production = _tier(tier) in PRODUCTION_TIERS
    return {'tier': tier, 'production': production, 'stops_on_evidence_untrusted': production,
            'blocked_floor_stops_when_untrusted': True}


def gate_stops(routing_result, tier, floor_of_control):
    """Does the gate exit non-zero on this routing result at this tier, for a control with this
    effective minimum? BLOCKED stops everywhere. EVIDENCE_UNTRUSTED stops at production tiers,
    and everywhere for a control whose floor is BLOCKED. DECISION_REQUIRED and below never stop:
    a decision owed is not a refusal observed. Visibility is untouched either way."""
    if routing_result not in PRECEDENCE:
        raise ValueError('%r is not a registered routing_result' % (routing_result,))
    if floor_of_control not in PRECEDENCE:
        raise ValueError('%r is not a registered routing_result' % (floor_of_control,))
    b = tier_behaviour(tier)
    if routing_result == 'BLOCKED':
        return True
    if routing_result == 'EVIDENCE_UNTRUSTED':
        return b['stops_on_evidence_untrusted'] or (floor_of_control == 'BLOCKED' and b['blocked_floor_stops_when_untrusted'])
    return False


def apply_tier(effective_minimum, tier):
    """ETFB section 4.0: environment_tier may only RAISE the floor. -> a new per-control mapping,
    never lower than the input. Today the tier raises nothing (see the module docstring: whether
    the AXES_AND_PHASES.md rows should raise floors beyond the rung is an owner decision); the
    function exists so that the only place a tier can touch a floor is one that cannot lower it."""
    _tier(tier)
    out = {}
    for control, base in (effective_minimum or {}).items():
        out[control] = precedence_max(base)
    return out


def human_controls(team_pattern):
    """-> {human control: human_control_availability} for the pattern."""
    return dict(HUMAN_CONTROL_TABLE[_pattern(team_pattern)])


def unvalidated_paths(team_pattern):
    """The UNVALIDATED HUMAN-WORKFLOW PATHS at this pattern, by name, sorted."""
    return sorted(k for k, v in human_controls(team_pattern).items() if v == HUMAN_CONTROL_UNVALIDATED)


def breach_authority(team_pattern):
    return dict(BREACH_AUTHORITY[_pattern(team_pattern)])


def _selftest():
    fails = []
    if not gate_stops('EVIDENCE_UNTRUSTED', 'prod', 'PROCEED') or gate_stops('EVIDENCE_UNTRUSTED', 'dev', 'PROCEED'):
        fails.append('tier behaviour on EVIDENCE_UNTRUSTED is wrong')
    if not gate_stops('EVIDENCE_UNTRUSTED', 'dev', 'BLOCKED'):
        fails.append('a BLOCKED-floor control did not stop when untrusted at dev')
    if human_controls('solo_dev')['approval_separation'] != HUMAN_CONTROL_UNVALIDATED:
        fails.append('solo_dev separation is not an unvalidated path')
    if apply_tier({'x': 'DECISION_REQUIRED'}, 'prod')['x'] != 'DECISION_REQUIRED':
        fails.append('apply_tier changed a floor')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('enforcement_axes selftest ok: production tiers stop on untrusted evidence, a BLOCKED floor '
          'stops everywhere, a tier lowers nothing, solo_dev reports unvalidated human-workflow paths. '
          'The full proof is tests/prove_enforcement_axes.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: enforcement_axes.py --self-test', file=sys.stderr)
    sys.exit(2)
