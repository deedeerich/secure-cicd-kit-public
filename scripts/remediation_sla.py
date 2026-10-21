#!/usr/bin/env python3
"""Severity, fix availability, the SLA clock, breach staging, the day-one cohort. (L47)

    "Already in production, fix it instead" with no date is PERMANENT AMNESTY, and it is the
    loophole every team eventually finds (ETFB section 8). These are the pure functions that put
    a date on it. They read nothing and write nothing; the ledger entry, the decisions and the
    NUMBERS are handed in, and the answer goes to whoever enforces.

EVERY NUMBER IS CONFIGURATION (ETFB section 8.2, section 13)

    The SLA table, the grace periods, the stall period and the re-check cadence are policy, not
    architecture -- capability_origin.OVERLAY_SPECIFIC_POLICY. They arrive in the registration's
    `numbers` block (scripts/policy_registration.py) and NOTHING here holds a value to fall back
    to: a missing number is POLICY_NUMBER_NOT_CONFIGURED, never a default. The owner's table is
    recorded in templates/policy-registration.example.json as the configured value.

SEVERITY (section 6)              derived under a VERSIONED formula; every scanner's number
                                  preserved; disagreement recorded, never averaged; downward
                                  override needs a named authority and an unexpired expiry.
FIX AVAILABILITY (section 7)      its own axis. Only FIX_AVAILABLE and MITIGATION_AVAILABLE admit
                                  a track. NO_FIX_AVAILABLE owes a decision and a re-check.
                                  Not established is a gap: DECISION_REQUIRED, never grandfathered.
THE CLOCK (section 8.3, 8.4)      from a CLAIMABLE first_seen (provenance_identity.observation_time
                                  tiers 1-2), otherwise from baseline establishment with the age
                                  recorded as unestablished -- "first observed by us on <date>;
                                  the finding may be older". A deadline may already be past.
BREACH (section 8.5)              staged: deadline -> DECISION_REQUIRED; grace -> the same;
                                  grace gone with no decision -> REOPENED_BY_LAPSE and the rung's
                                  lapsed-track floor. A decision after a lapse does not restore
                                  the deadline; the lapse stays in the history.
ANTI-LAUNDERING (section 6, 8.8)  new deadline = min(existing, re-score date + period). There
                                  is no function here that extends a deadline, by construction.
THE COHORT (section 8.4)          closed at establishment: only identities in the ledger at the
                                  establishment commit; an accepted, dated breach that resets no
                                  clock and never says compliant; a per-severity burn-down.

USAGE
    from remediation_sla import derive_severity, sla_deadline, rescore_deadline, track_state, ...
    python3 remediation_sla.py --self-test
"""
import datetime
import re
import sys

# Registered vocabulary, spelled once.
FIX_AVAILABLE = 'FIX_AVAILABLE'
MITIGATION_AVAILABLE = 'MITIGATION_AVAILABLE'
NO_FIX_AVAILABLE = 'NO_FIX_AVAILABLE'
FIX_AVAILABILITY_NOT_ESTABLISHED = 'FIX_AVAILABILITY_NOT_ESTABLISHED'
FIX_AVAILABILITY_VALUES = (FIX_AVAILABLE, MITIGATION_AVAILABLE, NO_FIX_AVAILABLE, FIX_AVAILABILITY_NOT_ESTABLISHED)

ON_TRACK = 'ON_TRACK'
BREACHED_ACCEPTED = 'BREACHED_ACCEPTED'
BREACHED_UNDECIDED = 'BREACHED_UNDECIDED'
CLOSED_VERIFIED = 'CLOSED_VERIFIED'
TRACK_STALLED = 'TRACK_STALLED'
TRACK_NOT_ADMITTED = 'TRACK_NOT_ADMITTED'

REOPENED_BY_LAPSE = 'REOPENED_BY_LAPSE'          # finding_classification
POTENTIALLY_ABSENT = 'POTENTIALLY_ABSENT'        # finding_classification
REMEDIATED = 'REMEDIATED'                        # disposition_type
MITIGATED = 'MITIGATED'
DECISION_REQUIRED = 'DECISION_REQUIRED'          # routing_result
PROCEED_WITH_ADVISORY = 'PROCEED_WITH_ADVISORY'
POLICY_NUMBER_NOT_CONFIGURED = 'POLICY_NUMBER_NOT_CONFIGURED'   # policy_resolution

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
# provenance_identity.observation_time: the claimable tiers.
claimable_sources = ('DECLARED_IN_CONTENT', 'SIDECAR')

# THE FORMULAS, BY VERSION. A formula is policy with a version string; a change is a declared
# event with the same reconciliation obligation as a scanner upgrade (section 6). Version 1:
# the highest scanner severity, raised one step when the finding is known to be exploited
# (exploitation signal) and one step when the cell is internet-facing (environmental modifier).
# Never lowered by a signal; capped at CRITICAL. An owner who wants different weights publishes
# a new version here; the old one keeps deriving what it always did.
FORMULAS = {'severity-formula/1': {'known_exploited': 1, 'internet_facing': 1}}

ISO = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _date(s):
    if not isinstance(s, str) or not ISO.match(s):
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def _iso(d):
    return d.isoformat() if d else None


def _number(numbers, *path):
    """-> (value, missing_name). Integers only; a bool is not a number."""
    cur = numbers or {}
    for p in path:
        cur = cur.get(p) if isinstance(cur, dict) else None
    if isinstance(cur, bool) or not isinstance(cur, int) or cur < 0:
        return None, '.'.join(path)
    return cur, None


def _not_configured(name, **extra):
    out = {'state': POLICY_NUMBER_NOT_CONFIGURED, 'routes_to': None,
           'why': '%s is not configured. It is a placeholder the design refuses to make a constant; '
                  'nothing can be computed without it and nothing here defaults it' % name}
    out.update(extra)
    return out


# ─────────────────────────────────────────────────────────────────────────────
def derive_severity(scanner_severities, numbers, today, signals=None, override=None):
    """ETFB section 6. -> {effective_severity | None, provisional, formula_version,
    scanner_severities (preserved), scanner_disagreement, signals, override, why}."""
    sev = dict((k, _s(v).upper()) for k, v in (scanner_severities or {}).items())
    out = {'effective_severity': None, 'provisional': None, 'formula_version': None,
           'scanner_severities': dict(scanner_severities or {}), 'scanner_disagreement': False,
           'signals': dict(signals or {}), 'override': None, 'why': ''}
    version = _s((numbers or {}).get('severity_formula_version'))
    if version not in FORMULAS:
        out['why'] = ('severity formula version %r is not one this kit can run (%s). An unversioned or '
                      'unknown formula silently re-dates every finding the day somebody edits it, so '
                      'nothing is derived' % (version or None, ', '.join(sorted(FORMULAS))))
        return out
    out['formula_version'] = version
    known = [v for v in sev.values() if v in SEVERITIES]
    bad = [k for k, v in sev.items() if v not in SEVERITIES]
    if bad:
        out['why'] = 'scanner(s) %s report a severity outside %s; not derived' % (', '.join(sorted(bad)), '/'.join(SEVERITIES))
        return out
    if not known:
        out['why'] = 'no scanner reported a severity; nothing to derive from, and nothing is assumed'
        return out
    idx = max(SEVERITIES.index(v) for v in known)
    out['provisional'] = SEVERITIES[idx]
    out['scanner_disagreement'] = len(set(known)) > 1
    for signal, steps in FORMULAS[version].items():
        if (signals or {}).get(signal) is True:
            idx = min(idx + steps, len(SEVERITIES) - 1)
    effective = SEVERITIES[idx]
    why = ('highest of %d scanner severit(y/ies)%s under %s'
           % (len(known), ' -- they DISAGREE, which is recorded for a human, never averaged' if out['scanner_disagreement'] else '',
              version))
    if override:
        value = _s(override.get('value')).upper()
        rec = {'value': value, 'applied': False, 'direction': None, 'why': ''}
        if value not in SEVERITIES:
            rec['why'] = 'override value %r is not a severity' % (override.get('value'),)
        elif SEVERITIES.index(value) > idx:
            rec.update(applied=True, direction='upward', why='upward is free: a strengthening')
            effective = value
        elif SEVERITIES.index(value) < idx:
            rec['direction'] = 'downward'
            auth, exp, reason = _s(override.get('authority')), _s(override.get('expires')), _s(override.get('reason'))
            expd, td = _date(exp), _date(today)
            if not (auth and reason and expd and td):
                rec['why'] = ('downward moves the SLA deadline, so it is a governance act: a named authority, '
                              'a reason and a readable expiry are required. Refused and recorded as attempted')
            elif expd < td:
                rec['why'] = 'the override expired on %s; silence never renews it. Refused' % exp
            else:
                rec.update(applied=True, why='attributed to %s until %s' % (auth, exp))
                effective = value
        else:
            rec['why'] = 'equal to the derived value; no change'
        out['override'] = rec
        why += '; override %s' % ('applied (%s)' % rec['direction'] if rec['applied'] else 'refused: ' + rec['why'])
    out['effective_severity'] = effective
    out['why'] = why
    return out


# ─────────────────────────────────────────────────────────────────────────────
def fix_availability_admits(value, numbers, established_on, today):
    """ETFB section 7. -> {state, value, admits_track, track_kind, closing_disposition,
    may_grandfather, routes_to, recheck_due, recheck_overdue, why}."""
    if value not in FIX_AVAILABILITY_VALUES:
        raise ValueError('%r is not a registered fix_availability value' % (value,))
    base = {'state': value, 'value': value, 'admits_track': False, 'track_kind': None,
            'closing_disposition': None, 'may_grandfather': False, 'routes_to': None,
            'recheck_due': None, 'recheck_overdue': False, 'why': ''}
    if value == FIX_AVAILABLE:
        base.update(admits_track=True, track_kind='fix', closing_disposition=REMEDIATED, may_grandfather=True,
                    why='a fix exists and applies here; the track closes when the scanner stops reproducing '
                        'the finding (REMEDIATED is self-invalidating)')
    elif value == MITIGATION_AVAILABLE:
        base.update(admits_track=True, track_kind='mitigation', closing_disposition=MITIGATED, may_grandfather=True,
                    why='no fix, a compensating control can be put in force; the track completes when the '
                        'control is in force and evidenced, closing to MITIGATED with its own re-verification '
                        'expiry. The finding remains open and observable')
    elif value == NO_FIX_AVAILABLE:
        cadence, missing = _number(numbers, 'no_fix_recheck_days')
        if missing:
            return _not_configured(missing, value=value, admits_track=False, may_grandfather=False,
                                   routes_to=DECISION_REQUIRED)
        est, td = _date(established_on), _date(today)
        due = est + datetime.timedelta(days=cadence) if est else None
        base.update(routes_to=DECISION_REQUIRED, recheck_due=_iso(due),
                    recheck_overdue=bool(due is None or (td and td > due)),
                    why='upstream has no fix: a DECISION is owed, not a schedule -- ACCEPTED_RISK with a named '
                        'authority and an expiry, or removal of the exposure. "No fix exists" is a claim with a '
                        'shelf life: re-establish it every %d days%s' % (cadence, '' if due and td and td <= due
                                                                           else ' -- OVERDUE, re-establish first'))
    else:
        base.update(routes_to=DECISION_REQUIRED,
                    why='nobody has established whether a fix exists. A gap, never a benign default: may not '
                        'take a track and may not be grandfathered until somebody establishes it')
    return base


# ─────────────────────────────────────────────────────────────────────────────
def sla_deadline(entry, numbers, established_on):
    """ETFB section 8.3-8.4. -> {state, deadline, clock_start, clock_start_basis, age_established,
    breached_at_establishment, routes_to, why}."""
    out = {'state': 'computed', 'deadline': None, 'clock_start': None, 'clock_start_basis': None,
           'age_established': entry.get('age_established') is True, 'breached_at_establishment': None,
           'routes_to': None, 'why': ''}
    severity = _s(entry.get('effective_severity')).upper()
    if severity not in SEVERITIES:
        out.update(state='no_severity', routes_to=DECISION_REQUIRED,
                   why='no effective severity, so no period applies; the SLA hangs entirely off severity')
        return out
    period, missing = _number(numbers, 'sla_period_days', severity)
    if missing:
        return _not_configured(missing, deadline=None, clock_start=None, clock_start_basis=None,
                               age_established=out['age_established'], breached_at_establishment=None)
    est = _date(established_on)
    src = _s((entry.get('first_seen_provenance') or {}).get('observed_at_source'))
    fs = _date(entry.get('first_seen'))
    if entry.get('age_established') is True:
        if src not in claimable_sources or not fs:
            out.update(state='unclaimable', clock_start_basis='unclaimable', routes_to=DECISION_REQUIRED,
                       why='the entry claims an established age from %r, which is not a claimable time source '
                           '(FILE_MTIME looks authoritative and is systematically wrong in the direction that '
                           'makes stale evidence look fresh). No deadline until the claim is corrected; the '
                           'clock is not quietly started at establishment either, because that would reward '
                           'the wrong claim with the later date' % (src or None))
            return out
        start, basis = fs, 'first_seen'
        why = 'first seen %s from a claimable source (%s); period %d days' % (_iso(fs), src, period)
    else:
        if not est:
            out.update(state='no_establishment', routes_to=DECISION_REQUIRED,
                       why='the age is not established and no baseline establishment date was given')
            return out
        start, basis = est, 'baseline_establishment'
        why = ('first observed by us on %s; the finding may be older. Age not established, so the clock '
               'runs from baseline establishment; period %d days' % (_iso(est), period))
    deadline = start + datetime.timedelta(days=period)
    out.update(deadline=_iso(deadline), clock_start=_iso(start), clock_start_basis=basis, why=why,
               breached_at_establishment=(bool(est and deadline < est) if est else None))
    if out['breached_at_establishment']:
        out['why'] += '. Deadline %s is before establishment: BREACHED ON DAY ONE' % _iso(deadline)
    return out


def rescore_deadline(existing_deadline, rescore_date, new_severity, numbers):
    """ETFB section 6: new deadline = min(existing, re-score date + period(new severity)).
    -> {state, deadline, attempted, moved: earlier | unchanged | set, why}. Nothing extends."""
    severity = _s(new_severity).upper()
    period, missing = _number(numbers, 'sla_period_days', severity)
    if missing:
        return _not_configured(missing, deadline=existing_deadline, attempted=None, moved=None)
    rd = _date(rescore_date)
    if not rd:
        return {'state': 'bad_date', 'deadline': existing_deadline, 'attempted': None, 'moved': None,
                'why': 're-score date %r is not an ISO date' % (rescore_date,)}
    attempted = rd + datetime.timedelta(days=period)
    existing = _date(existing_deadline)
    if existing is None:
        return {'state': 'computed', 'deadline': _iso(attempted), 'attempted': _iso(attempted), 'moved': 'set',
                'why': 'no existing deadline; set from the re-score date'}
    new = min(existing, attempted)
    moved = 'earlier' if new < existing else 'unchanged'
    return {'state': 'computed', 'deadline': _iso(new), 'attempted': _iso(attempted), 'moved': moved,
            'why': ('re-score to %s on %s would give %s; the deadline is min(existing %s, that) = %s. %s'
                    % (severity, rescore_date, _iso(attempted), _iso(existing), _iso(new),
                       'An upward re-score brings a deadline earlier' if moved == 'earlier'
                       else 'Nothing extends a deadline: the attempt is recorded and the deadline stands'))}


# ─────────────────────────────────────────────────────────────────────────────
def _decisions(decisions, today):
    """Dated decisions by a named authority, with their expiry state."""
    td = _date(today)
    out = []
    for d in decisions or []:
        if not isinstance(d, dict):
            continue
        auth, exp, dd = _s(d.get('authority')), _date(d.get('expires')), _date(d.get('date'))
        rec = {'kind': _s(d.get('kind')), 'date': _iso(dd), 'authority': auth, 'expires': _iso(exp),
               'valid': bool(auth and exp and dd and td), 'in_force': False, 'why': ''}
        if not rec['valid']:
            rec['why'] = 'a decision needs a named authority, a date and a readable expiry; this one is not a decision'
        elif exp < td:
            rec['why'] = 'expired %s; silence never renews it' % _iso(exp)
        else:
            rec['in_force'] = True
        out.append(rec)
    return out


def track_state(entry, decisions, numbers, today, rung):
    """ETFB sections 7, 8.5, 8.7, 8.8 rules 6-7. -> {state, classification, control_class, routes_to,
    deadline, grace_ends, decisions, lapses, record, why}.

    `entry`: effective_severity, fix_availability, sla_deadline, scanner_reproduces,
             coverage_demonstrated, [ticket_closed -- ignored, deliberately].
    `rung`:  the effective rung; the routing is the rung's floor for the control class.
    """
    sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
    from rung_ladder import rung_floor, precedence_max
    floor = rung_floor(rung)
    severity = _s(entry.get('effective_severity')).upper()
    out = {'state': None, 'classification': None, 'control_class': 'pre_existing_on_track',
           'routes_to': None, 'deadline': entry.get('sla_deadline'), 'grace_ends': None,
           'decisions': _decisions(decisions, today), 'lapses': [], 'record': '', 'why': ''}
    fix = _s(entry.get('fix_availability'))
    fa = fix_availability_admits(fix if fix in FIX_AVAILABILITY_VALUES else FIX_AVAILABILITY_NOT_ESTABLISHED,
                                 numbers, established_on=entry.get('fix_availability_established_on'), today=today)
    in_force = [d for d in out['decisions'] if d['in_force']]
    # Closure: the scanner clears a finding; a ticket never does (rule 7).
    if entry.get('scanner_reproduces') is False:
        if entry.get('coverage_demonstrated') is True:
            out.update(state=CLOSED_VERIFIED, record='closed: the scanner no longer reproduces it over '
                       'demonstrated coverage', why='verified closure')
            return out
        out['classification'] = POTENTIALLY_ABSENT
    # Admission: only an established fix or mitigation takes a track; NO_FIX_AVAILABLE needs a decision.
    if not fa['admits_track'] and not in_force:
        out.update(state=TRACK_NOT_ADMITTED, routes_to=DECISION_REQUIRED,
                   record='not on a track: ' + fa['why'], why=fa['why'])
        return out
    if severity not in SEVERITIES:
        out.update(state=TRACK_NOT_ADMITTED, routes_to=DECISION_REQUIRED, why='no effective severity')
        return out
    grace, missing = _number(numbers, 'breach_grace_days', severity)
    if missing:
        return _not_configured(missing, classification=None, control_class=None, deadline=entry.get('sla_deadline'),
                               grace_ends=None, decisions=out['decisions'], lapses=[], record='')
    td, dl = _date(today), _date(entry.get('sla_deadline'))
    if not td or not dl:
        out.update(state=TRACK_NOT_ADMITTED, routes_to=DECISION_REQUIRED,
                   why='no deadline (%r) or today (%r); a track without a date is amnesty' % (entry.get('sla_deadline'), today))
        return out
    grace_ends = dl + datetime.timedelta(days=grace)
    out['grace_ends'] = _iso(grace_ends)
    out['lapses'] = [d for d in out['decisions'] if d['valid'] and not d['in_force']]
    if td <= dl:
        out.update(state=ON_TRACK, routes_to=floor['pre_existing_on_track'],
                   record='on track; deadline %s' % _iso(dl), why='unexpired')
        return out
    # Breached. A decision in force accepts the breach -- the record says breached, never compliant.
    if in_force:
        d = max(in_force, key=lambda x: x['expires'])
        if td > grace_ends and any(x['date'] and _date(x['date']) > grace_ends for x in in_force):
            out['lapses'].append({'kind': 'grace_expired_before_decision', 'date': _iso(grace_ends),
                                  'why': 'the grace ended on %s with no decision; the later decision is a new '
                                         'dated decision and does not restore the original deadline' % _iso(grace_ends)})
        out.update(state=BREACHED_ACCEPTED, routes_to=floor['pre_existing_on_track'],
                   record='breached %s; accepted until %s; by %s' % (_iso(dl), d['expires'], d['authority']),
                   why='a dated decision by a named authority is in force; the deadline is unchanged')
        return out
    if td <= grace_ends:
        out.update(state=BREACHED_UNDECIDED, routes_to=precedence_max(DECISION_REQUIRED, floor['pre_existing_on_track']),
                   record='breached %s; awaiting decision until %s' % (_iso(dl), _iso(grace_ends)),
                   why='deadline passed; the escalation authority owes a new dated decision within the grace')
        return out
    out.update(state=BREACHED_UNDECIDED, classification=REOPENED_BY_LAPSE, control_class='pre_existing_track_lapsed',
               routes_to=floor['pre_existing_track_lapsed'],
               record='breached %s; grace ended %s; no decision: REOPENED_BY_LAPSE' % (_iso(dl), _iso(grace_ends)),
               why='the finding never changed; its disposition expired. In enforcement it is a NEW finding; in '
                   'the record it keeps its first_seen and the lapse is dated')
    return out


def track_stalled(closure_dates, numbers, today):
    """ETFB section 8.8 rule 5. -> {state, routes_to, last_closure, why}."""
    period, missing = _number(numbers, 'track_stall_period_days')
    if missing:
        return _not_configured(missing, last_closure=None)
    td = _date(today)
    dates = sorted(d for d in (_date(x) for x in closure_dates or []) if d)
    last = dates[-1] if dates else None
    if last and td and (td - last).days <= period:
        return {'state': 'active', 'routes_to': None, 'last_closure': _iso(last),
                'why': 'a verified closure within %d days' % period}
    return {'state': TRACK_STALLED, 'routes_to': DECISION_REQUIRED, 'last_closure': _iso(last),
            'why': 'zero verified closures in %d days: amnesty with paperwork, DECISION_REQUIRED at the next '
                   'promotion review regardless of how many entries are unexpired' % period}


# ─────────────────────────────────────────────────────────────────────────────
def day_one_cohort(entries_at_establishment, decision, numbers, today):
    """ETFB section 8.4. -> {members, refused, member_records, resets_clock, why}.

    `entries_at_establishment`: ledger entries AT THE ESTABLISHMENT COMMIT (the caller reads them
    there; nothing later may join). `decision`: {decided_on, authority, establishment_commit,
    burn_down: {severity: date}, members: [identities]}.
    """
    out = {'members': [], 'refused': [], 'member_records': [], 'resets_clock': False, 'why': ''}
    auth, decided = _s(decision.get('authority')), _date(decision.get('decided_on'))
    if not auth or not decided or not _s(decision.get('establishment_commit')):
        out['refused'] = [{'identity': i, 'why': 'the cohort decision has no named authority, date or '
                                                'establishment commit; it is not a decision'}
                          for i in decision.get('members') or []]
        out['why'] = 'cohort decision refused'
        return out
    present = dict((e.get('identity'), e) for e in entries_at_establishment or [])
    burn = decision.get('burn_down') or {}
    td = _date(today)
    for ident in decision.get('members') or []:
        e = present.get(ident)
        if e is None:
            out['refused'].append({'identity': ident, 'why': 'not in the ledger at the establishment commit. The '
                                                              'cohort is closed at establishment; this is a '
                                                              'per-finding decision with a per-finding approver'})
            continue
        dl = _date(e.get('sla_deadline'))
        if not dl or dl >= decided:
            out['refused'].append({'identity': ident, 'why': 'not breached at establishment (deadline %r); the '
                                                              'cohort holds the day-one BREACH set only'
                                                              % e.get('sla_deadline')})
            continue
        sev = _s(e.get('effective_severity')).upper()
        until = _date(burn.get(sev))
        if not until:
            out['refused'].append({'identity': ident, 'why': 'no burn-down sub-deadline for severity %r; the '
                                                              'cohort must not all come due on one morning, and '
                                                              'a member with no date is open-ended' % (sev or None)})
            continue
        rec = {'identity': ident, 'effective_severity': sev, 'sla_deadline': e.get('sla_deadline'),
               'accepted_until': _iso(until), 'authority': auth, 'decided_on': _iso(decided)}
        if td and td > until:
            rec.update(state=BREACHED_UNDECIDED, classification=REOPENED_BY_LAPSE,
                       record='breached %s; cohort acceptance until %s by %s has LAPSED' % (e.get('sla_deadline'), _iso(until), auth))
        else:
            rec.update(state=BREACHED_ACCEPTED, classification=None,
                       record='breached %s; accepted until %s; by %s; burn-down per severity' % (e.get('sla_deadline'), _iso(until), auth))
        out['members'].append(ident)
        out['member_records'].append(rec)
    out['why'] = '%d member(s), %d refused; no clock was reset' % (len(out['members']), len(out['refused']))
    return out


def baseline_sanity(entries, today):
    """ETFB section 8.4: a baseline with zero day-one breaches is either a young repository or a
    laundered baseline. -> {entries, day_one_breaches, suspicious, why}."""
    td = _date(today)
    breached = sum(1 for e in entries or [] if _date(e.get('sla_deadline')) and td and _date(e.get('sla_deadline')) < td)
    suspicious = bool(entries) and breached == 0
    return {'entries': len(entries or []), 'day_one_breaches': breached, 'suspicious': suspicious,
            'why': ('zero day-one breaches over %d entries: either a young repository or a laundered '
                    'baseline. A finding about the baseline, not a fact about the code' % len(entries or []))
            if suspicious else '%d of %d entries breached at establishment' % (breached, len(entries or []))}


def _selftest():
    fails = []
    n = {'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 180, 'LOW': 365},
         'breach_grace_days': {'CRITICAL': 0, 'HIGH': 7, 'MEDIUM': 14, 'LOW': 14},
         'severity_formula_version': 'severity-formula/1', 'no_fix_recheck_days': 30, 'track_stall_period_days': 90}
    if derive_severity({'a': 'LOW', 'b': 'HIGH'}, n, '2026-10-14')['effective_severity'] != 'HIGH':
        fails.append('severity is not the highest')
    if rescore_deadline('2026-02-09', '2026-02-01', 'LOW', n)['deadline'] != '2026-02-09':
        fails.append('a downward re-score extended a deadline')
    if sla_deadline({'effective_severity': 'HIGH', 'age_established': True, 'first_seen': '2026-01-01',
                     'first_seen_provenance': {'observed_at_source': 'FILE_MTIME'}}, n, '2026-10-01')['deadline']:
        fails.append('an mtime-dated age produced a deadline')
    if sla_deadline({'effective_severity': 'HIGH'}, {}, '2026-10-01')['state'] != POLICY_NUMBER_NOT_CONFIGURED:
        fails.append('a missing period defaulted')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('remediation_sla selftest ok: highest severity, nothing extends a deadline, an unclaimable age gets '
          'no deadline, a missing number refuses. The full proof is tests/prove_remediation_sla.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: remediation_sla.py --self-test', file=sys.stderr)
    sys.exit(2)
