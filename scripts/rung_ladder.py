#!/usr/bin/env python3
"""The RUNG LADDER: the derivation table ETFB section 13 said was owed, as pure functions. (L32)

WHAT A RUNG IS (ETFB sections 1-4)

    The business's declared posture per (repository, environment) cell. It sits ABOVE policy_mode,
    team_pattern and environment_tier: those are read downstream of it, never beside it. A rung
    does not say "block" or "not block". It sets, per control, the WEAKEST routing result that
    control may contribute; the run's result is the precedence maximum across controls, using the
    order routing_result already registers:

        BLOCKED > EVIDENCE_UNTRUSTED > DECISION_REQUIRED > PROCEED_WITH_ADVISORY > PROCEED

THE DERIVATION TABLE (ETFB section 1.1, verbatim; see docs/architecture/RUNG_DERIVATION_TABLE.md)

    control class                  crawl                   walk                 run
    secrets                        BLOCKED                 BLOCKED              BLOCKED
    new_critical_high              PROCEED_WITH_ADVISORY   DECISION_REQUIRED    BLOCKED
    pre_existing_on_track          PROCEED_WITH_ADVISORY   DECISION_REQUIRED    PROCEED_WITH_ADVISORY
    pre_existing_track_lapsed      PROCEED_WITH_ADVISORY   DECISION_REQUIRED    BLOCKED
    other_findings (medium/low)    PROCEED_WITH_ADVISORY   DECISION_REQUIRED    DECISION_REQUIRED

    policy_mode is DERIVED:  crawl -> adoption,  walk -> adoption,  run -> strict.
    (ETFB section 13: "policy_mode.adoption remains close to crawl and policy_mode.strict close to
    run". walk's blocking set -- secrets plus cherry-picks -- is adoption's "non-secret findings
    report without blocking" plus the cherry-picked set, which is its own mechanism below.)

THE FLOOR INVARIANT (ETFB section 2)

    effective_minimum(control) = precedence_max(rung_floor(control), cherry_pick(control))

    A cherry-pick BELOW the floor is not applied-then-overridden and not silently dropped. It is a
    POLICY DEFECT that fails the policy check, by name. The downward direction has no
    representation: there is no field in which a pick can express "less than the rung".

WHAT THIS DOES NOT DO

    Read anything. The registration file is read by scripts/policy_registration.py, from the
    protected default branch; this module is handed the parsed cell and the numbers. It holds NO
    constant for any number the design calls a placeholder: the consecutive-run count for promotion
    is read from the numbers handed in, and a missing number REFUSES (POLICY_NUMBER_NOT_CONFIGURED).

USAGE
    from rung_ladder import rung_floor, effective_minimum, derive_policy_mode, ...
    python3 rung_ladder.py --self-test
"""
import datetime
import re
import sys

# routing_result, lowest to highest. precedence_max picks the right-most.
PRECEDENCE = ('PROCEED', 'PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'EVIDENCE_UNTRUSTED', 'BLOCKED')

# enforcement_rung (assurance-taxonomy.yaml), lowest to highest.
RUNGS = ('crawl', 'walk', 'run')

# environment_tier along the promotion path. uat and prod are both production tiers.
tier_order = ('sandbox', 'dev', 'test', 'uat', 'prod')
PRODUCTION_TIERS = ('uat', 'prod')

# policy_resolution (assurance-taxonomy.yaml). Spelled once, here.
POLICY_RESOLVED = 'POLICY_RESOLVED'
POLICY_MODE_SUPPLIED = 'POLICY_MODE_SUPPLIED'
CHERRY_PICK_BELOW_FLOOR = 'CHERRY_PICK_BELOW_FLOOR'
CELLS_NOT_MONOTONE = 'CELLS_NOT_MONOTONE'
CELL_NOT_REGISTERED = 'CELL_NOT_REGISTERED'
REGISTRATION_UNAVAILABLE = 'REGISTRATION_UNAVAILABLE'
POLICY_NUMBER_NOT_CONFIGURED = 'POLICY_NUMBER_NOT_CONFIGURED'
RUNG_EFFECTIVE_BELOW_DECLARED = 'RUNG_EFFECTIVE_BELOW_DECLARED'

# control_weakening, reused for a demotion (ETFB section 4.0: "declaring downward is a weakening
# event ... at least as visible as disabling one scanner").
GATE_SOFTENED = 'GATE_SOFTENED'
WEAKENING_IN_FORCE = 'WEAKENING_IN_FORCE'
WEAKENING_ATTRIBUTED = 'WEAKENING_ATTRIBUTED'
WEAKENING_UNATTRIBUTED = 'WEAKENING_UNATTRIBUTED'
WEAKENING_EXCEPTION_EXPIRED = 'WEAKENING_EXCEPTION_EXPIRED'
DECISION_REQUIRED = 'DECISION_REQUIRED'
PROCEED_WITH_ADVISORY = 'PROCEED_WITH_ADVISORY'

control_classes = ('secrets', 'new_critical_high', 'pre_existing_on_track',
                   'pre_existing_track_lapsed', 'other_findings')

# ETFB section 1.1. Design, not a placeholder: the table is the owner's model expressed as minimum
# routing results. The one row the table lists and this omits is "cherry-picked set", which is an
# OUTPUT of effective_minimum rather than a floor of its own.
FLOOR = {
    'secrets':                   {'crawl': 'BLOCKED', 'walk': 'BLOCKED', 'run': 'BLOCKED'},
    'new_critical_high':         {'crawl': 'PROCEED_WITH_ADVISORY', 'walk': 'DECISION_REQUIRED', 'run': 'BLOCKED'},
    'pre_existing_on_track':     {'crawl': 'PROCEED_WITH_ADVISORY', 'walk': 'DECISION_REQUIRED', 'run': 'PROCEED_WITH_ADVISORY'},
    'pre_existing_track_lapsed': {'crawl': 'PROCEED_WITH_ADVISORY', 'walk': 'DECISION_REQUIRED', 'run': 'BLOCKED'},
    'other_findings':            {'crawl': 'PROCEED_WITH_ADVISORY', 'walk': 'DECISION_REQUIRED', 'run': 'DECISION_REQUIRED'},
}

# THE TABLE IS NOT MONOTONE ON ONE ROW, AND THE DESIGN SAYS IT IS. ETFB section 1.1 states "for
# every control, run is at least as strong as walk" and then gives pre_existing_on_track as
# DECISION_REQUIRED at walk and PROCEED_WITH_ADVISORY at run. That row is the mechanism the whole
# document exists for -- "run does not grant amnesty; it grants a schedule" -- so the value is kept
# verbatim and the exemption is NAMED here rather than the check being weakened to let it pass.
# Reading: at walk a pre-existing finding owes a disposition (DECISION_REQUIRED); at run the track
# IS the disposition (ACCEPTED_RISK plus a track reference, section 8.1), and while it is unexpired
# the run proceeds with advisory. Whether walk should read the same once a track exists is an OWNER
# DECISION recorded in the lane report; nothing here decides it.
monotone_exempt = ('pre_existing_on_track',)

POLICY_MODE_OF_RUNG = {'crawl': 'adoption', 'walk': 'adoption', 'run': 'strict'}

# A NAMED control (a scanner job) is cherry-picked against the weakest non-secret row, because a
# pick on a scanner applies to every finding it reports. The secret scanner is the secrets class.
NAMED_CONTROL_CLASS = {'secret-scan': 'secrets'}
DEFAULT_NAMED_CLASS = 'other_findings'

# ETFB section 4.3: what each promotion must evidence. Every item is an evidence REFERENCE, never
# a boolean -- "configuration is not evidence". The consecutive-run item carries a count that is
# compared against the configured number.
PROMOTION_EVIDENCE = {
    'walk': ('controls_executed_at_baseline', 'ledger_populated_and_owned', 'entries_classified',
             'human_controls_assessed'),
    'run': ('baseline_forced_failure_demonstrated', 'track_closure_verified',
            'day_one_fix_availability_established'),
}

ISO_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def precedence_max(*results):
    """The registered precedence maximum. An unregistered value is refused, not ranked."""
    best = -1
    for r in results:
        if r not in PRECEDENCE:
            raise ValueError('%r is not a registered routing_result' % (r,))
        best = max(best, PRECEDENCE.index(r))
    if best < 0:
        raise ValueError('precedence_max of nothing')
    return PRECEDENCE[best]


def rung_index(rung):
    if rung not in RUNGS:
        raise ValueError('%r is not a registered enforcement_rung (crawl | walk | run)' % (rung,))
    return RUNGS.index(rung)


def rung_floor(rung):
    """-> {control class: minimum routing result} for the rung. ETFB section 1.1."""
    rung_index(rung)
    return dict((c, FLOOR[c][rung]) for c in control_classes)


def derive_policy_mode(rung):
    """policy_mode is DERIVED from the rung and recorded as such. Never settable by a caller."""
    rung_index(rung)
    return POLICY_MODE_OF_RUNG[rung]


def refuse_supplied_policy_mode(supplied_inputs):
    """ETFB section 4.0 / 13: a run in which policy_mode was SUPPLIED rather than computed fails.

    `supplied_inputs` is the mapping of inputs the run actually received (not the workflow's
    declared inputs). Any spelling of policy_mode present -- with any value, including the one
    the derivation would produce -- is a refusal: a derived value a caller can still override is
    not derived.
    """
    for key in (supplied_inputs or {}):
        if re.sub(r'[^a-z]', '', str(key).lower()) == 'policymode':
            return {'state': POLICY_MODE_SUPPLIED, 'input': str(key),
                    'why': 'policy_mode was supplied as input %r. It is derived from the registered '
                           'rung and recorded as such; a run that received one has a declared posture '
                           'and a supplied one, and the gate must not have to choose' % str(key)}
    return {'state': POLICY_RESOLVED, 'input': None, 'why': 'no policy_mode input was received'}


def effective_minimum(rung, cherry_picks):
    """ETFB section 2. -> {state, rung, floor, effective, divergences, defects, policy_mode}.

    `cherry_picks`: [{control, minimum, reason, authority, expiry | review_trigger}]. `control` is
    a control class or a named control. A pick equal to the floor is recorded and changes nothing;
    one above it is applied; one below it is a POLICY DEFECT and the state is
    CHERRY_PICK_BELOW_FLOOR. The effective set never contains the defective value.
    """
    floor = rung_floor(rung)
    effective = dict(floor)
    divergences, defects = [], []
    for i, pick in enumerate(cherry_picks or []):
        if not isinstance(pick, dict):
            defects.append('cherry-pick %d is not a mapping' % i)
            continue
        control = _s(pick.get('control'))
        minimum = _s(pick.get('minimum'))
        if not control:
            defects.append('cherry-pick %d names no control' % i)
            continue
        if minimum not in PRECEDENCE:
            defects.append('cherry-pick on %s asks for %r, which is not a registered routing_result; '
                           'an unregistered minimum cannot be compared with the floor, so it is refused'
                           % (control, minimum or None))
            continue
        cls = control if control in control_classes else NAMED_CONTROL_CLASS.get(control, DEFAULT_NAMED_CLASS)
        base = floor[cls]
        if precedence_max(base, minimum) != minimum:
            # BELOW THE FLOOR. Named, refused, and NOT applied.
            defects.append('cherry-pick on %s asks for %s, below the %s floor %s (%s). A tier is a '
                           'floor; cherry-picks may only strengthen it. This is %s wearing %s\'s label'
                           % (control, minimum, rung, base, cls, 'a weaker rung', rung))
            continue
        if minimum == base:
            divergences.append({'control': control, 'floor': base, 'effective': minimum,
                                'direction': 'none', 'note': 'equal to the floor; recorded, no change',
                                'reason': _s(pick.get('reason')), 'authority': _s(pick.get('authority'))})
            continue
        effective[control] = minimum
        divergences.append({'control': control, 'floor': base, 'effective': minimum,
                            'direction': 'strengthening', 'reason': _s(pick.get('reason')),
                            'authority': _s(pick.get('authority'))})
    return {'state': CHERRY_PICK_BELOW_FLOOR if defects else POLICY_RESOLVED, 'rung': rung,
            'floor': floor, 'effective': effective, 'divergences': divergences, 'defects': defects,
            'policy_mode': derive_policy_mode(rung)}


def check_cells_monotone(cells):
    """ETFB section 4.1: rung(sandbox) <= rung(dev) <= rung(test) <= rung(uat) = rung(prod).

    `cells`: {environment name: {tier, rung, ...}}. -> list of defects (empty is good). Two cells
    at the same tier must agree, since the tier is what orders them.
    """
    defects = []
    by_tier = {}
    for name, cell in (cells or {}).items():
        tier, rung = _s((cell or {}).get('tier')), _s((cell or {}).get('rung'))
        if tier not in tier_order:
            defects.append('cell %s: tier %r is not a registered environment_tier' % (name, tier or None))
            continue
        if rung not in RUNGS:
            defects.append('cell %s: rung %r is not a registered enforcement_rung' % (name, rung or None))
            continue
        by_tier.setdefault(tier, []).append((name, rung))
    if defects:
        return defects
    for tier, items in by_tier.items():
        rungs = set(r for _n, r in items)
        if len(rungs) > 1:
            defects.append('tier %s holds cells at different rungs (%s); the tier orders the cells, so '
                           'they must agree' % (tier, ', '.join('%s=%s' % x for x in sorted(items))))
    prev = None
    for tier in tier_order:
        if tier not in by_tier:
            continue
        name, rung = by_tier[tier][0]
        if prev and rung_index(rung) < rung_index(prev[1]):
            defects.append('rung(%s)=%s is below rung(%s)=%s: the ladder must be monotone along the '
                           'promotion path, or everything merges at the lower rung and is discovered '
                           'at the promotion gate' % (tier, rung, prev[0], prev[1]))
        prev = (tier, rung)
    uat, prod = by_tier.get('uat'), by_tier.get('prod')
    if uat and prod and uat[0][1] != prod[0][1]:
        defects.append('rung(uat)=%s != rung(prod)=%s: uat and prod are both production tiers and the '
                       'equality is not a choice' % (uat[0][1], prod[0][1]))
    return defects


def rung_for_pull_request(cells):
    """ETFB section 4.1: a PR is evaluated at the rung of the highest environment the merged branch
    can reach without a further human gate. -> (environment name, rung) or (None, None)."""
    best = None
    for name, cell in (cells or {}).items():
        cell = cell or {}
        if cell.get('reachable_from_merge_without_human_gate') is not True:
            continue
        tier, rung = _s(cell.get('tier')), _s(cell.get('rung'))
        if tier not in tier_order or rung not in RUNGS:
            continue
        key = (tier_order.index(tier), rung_index(rung))
        if best is None or key > best[0]:
            best = (key, name, rung)
    return (best[1], best[2]) if best else (None, None)


def effective_rung(cell, numbers):
    """ETFB section 4.0/4.3: the declaration names the TARGET; the evidence sets the EFFECTIVE.

    -> {state, declared, effective, missing: [what is not evidenced], why}. The gate obeys
    `effective`; the record carries both. The consecutive-run count is read from `numbers`
    ('promotion_consecutive_clean_runs'); absent, this REFUSES rather than defaulting.
    """
    declared = _s((cell or {}).get('rung'))
    if declared not in RUNGS:
        return {'state': CELL_NOT_REGISTERED, 'declared': declared or None, 'effective': None,
                'missing': [], 'why': 'the cell declares rung %r, which is not registered' % (declared or None)}
    need = (numbers or {}).get('promotion_consecutive_clean_runs')
    if not isinstance(need, int) or isinstance(need, bool) or need < 1:
        return {'state': POLICY_NUMBER_NOT_CONFIGURED, 'declared': declared, 'effective': None,
                'missing': ['promotion_consecutive_clean_runs'],
                'why': 'promotion_consecutive_clean_runs is not configured (%r). It is a placeholder '
                       'the design refuses to make a constant, so nothing can be evidenced without it'
                       % (need,)}
    evidence = (cell or {}).get('promotion_evidence') or {}
    effective, missing = 'crawl', []
    for rung in ('walk', 'run'):
        if rung_index(rung) > rung_index(declared):
            break
        got = evidence.get(rung) or {}
        lacking = []
        for item in PROMOTION_EVIDENCE[rung]:
            v = got.get(item)
            if item == 'controls_executed_at_baseline':
                runs = (v or {}).get('consecutive_clean_runs') if isinstance(v, dict) else None
                ref = _s((v or {}).get('evidence_ref')) if isinstance(v, dict) else ''
                if not isinstance(runs, int) or runs < need or not ref:
                    lacking.append('%s (need %d consecutive clean runs with an evidence ref; have %r)'
                                   % (item, need, runs))
            elif not _s(v):
                lacking.append(item)
        if lacking:
            missing.extend('%s: %s' % (rung, x) for x in lacking)
            break
        effective = rung
    state = POLICY_RESOLVED if effective == declared else RUNG_EFFECTIVE_BELOW_DECLARED
    return {'state': state, 'declared': declared, 'effective': effective, 'missing': missing,
            'why': ('declared and effective agree' if state == POLICY_RESOLVED else
                    'declared %s, effective %s: the promotion evidence of section 4.3 is incomplete. '
                    'The gate obeys the effective rung; the record carries both' % (declared, effective))}


def _expiry_state(expires, today):
    """Reuses the posture record's rule: an expiry must be a real YYYY-MM-DD; unreadable is expired."""
    if not expires:
        return None
    if not ISO_DATE.match(expires):
        return WEAKENING_EXCEPTION_EXPIRED
    try:
        exp = datetime.date.fromisoformat(expires)
    except ValueError:
        return WEAKENING_EXCEPTION_EXPIRED
    return WEAKENING_EXCEPTION_EXPIRED if exp < datetime.date.fromisoformat(today) else None


def demotion_record(history, today):
    """ETFB section 4.0/4.2: a demotion is a weakening event. -> [posture rows] for each downward
    move in `history` ([{from, to, reason, authority, expires, date}]). A promotion records nothing
    here (strengthening takes effect at once)."""
    rows = []
    for i, ev in enumerate(history or []):
        ev = ev or {}
        src, dst = _s(ev.get('from')), _s(ev.get('to'))
        if src not in RUNGS or dst not in RUNGS or rung_index(dst) >= rung_index(src):
            continue
        reason, authority, expires = _s(ev.get('reason')), _s(ev.get('authority')), _s(ev.get('expires'))
        if reason and authority and expires:
            attribution = _expiry_state(expires, today) or WEAKENING_ATTRIBUTED
        else:
            attribution = WEAKENING_UNATTRIBUTED
        routes = PROCEED_WITH_ADVISORY if attribution == WEAKENING_ATTRIBUTED else DECISION_REQUIRED
        rows.append({'input': 'rung demotion %d' % i, 'class': GATE_SOFTENED, 'control': 'rung',
                     'baseline': src, 'value': dst, 'state': WEAKENING_IN_FORCE,
                     'attribution': attribution, 'routes_to': routes, 'reason': reason,
                     'authority': authority, 'expires': expires, 'date': _s(ev.get('date')),
                     'why': ('a demotion without a reason, an authority and an expiry is a permanent '
                             'quiet retreat; silence never renews it' if attribution != WEAKENING_ATTRIBUTED
                             else 'attributed and unexpired; recorded on every affected run')})
    return rows


def _selftest():
    fails = []
    if precedence_max('PROCEED', 'DECISION_REQUIRED', 'PROCEED_WITH_ADVISORY') != 'DECISION_REQUIRED':
        fails.append('precedence_max is not the registered order')
    try:
        precedence_max('PASS')
        fails.append('an unregistered routing_result was ranked')
    except ValueError:
        pass
    for c in control_classes:
        vals = [FLOOR[c][r] for r in RUNGS]
        monotone = [precedence_max(*vals[:i + 1]) for i in range(3)] == vals
        if monotone == (c in monotone_exempt):
            fails.append('FLOOR monotonicity on %s does not match monotone_exempt: an exemption that '
                         'is not needed, or a non-monotone row that is not named' % c)
    r = effective_minimum('walk', [{'control': 'other_findings', 'minimum': 'PROCEED', 'reason': 'x',
                                    'authority': 'y'}])
    if r['state'] != CHERRY_PICK_BELOW_FLOOR or r['effective']['other_findings'] != 'DECISION_REQUIRED':
        fails.append('a below-floor pick on a control class was applied or not refused')
    if refuse_supplied_policy_mode({'Policy_Mode': 'strict'})['state'] != POLICY_MODE_SUPPLIED:
        fails.append('a supplied policy_mode slipped through on spelling')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('rung_ladder selftest ok: the floor table is monotone on every row but the one it names, a '
          'below-floor cherry-pick is a named defect, a supplied policy_mode is refused. The full '
          'proof is tests/prove_rung_ladder.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: rung_ladder.py --self-test   (library: from rung_ladder import effective_minimum)',
          file=sys.stderr)
    sys.exit(2)
