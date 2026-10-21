#!/usr/bin/env python3
"""Severity, fix availability, the SLA clock, breach staging, anti-laundering, the day-one cohort.

WHY THIS EXISTS (ledger L47; ETFB sections 6, 7, 8; TICKETING_CONTRACT.md 5.1-5.2, 5.6)

    "Already in production, fix it instead" with no date is permanent amnesty. These are the pure
    functions that put a date on it, proven over fixtures with every number read from
    configuration:

      1  SEVERITY IS DERIVED, NOT COPIED, WITH A FORMULA VERSION. Every scanner's number is
         preserved; disagreement is recorded, never averaged; the provisional value is the highest;
         an unknown formula version refuses. Upward override is free; downward needs a named
         authority and an expiry or it is refused and recorded as attempted.
      2  FIX AVAILABILITY IS ITS OWN AXIS. Only FIX_AVAILABLE and MITIGATION_AVAILABLE admit a
         track; NO_FIX_AVAILABLE needs a decision and a re-check cadence; not-established is a gap
         that routes DECISION_REQUIRED and may not be grandfathered.
      3  THE CLOCK STARTS AT A CLAIMABLE first_seen, OTHERWISE AT BASELINE ESTABLISHMENT with
         the age recorded as unestablished -- never asserted as an age. An entry that CLAIMS an
         established age from a non-claimable source gets no deadline at all. (Adversarial.)
      4  A FINDING OLDER THAN ITS SLA IS BREACHED ON DAY ONE. The deadline may already be past.
      5  BREACH IS STAGED: deadline passes -> DECISION_REQUIRED; grace (per severity, CRITICAL
         none) -> still DECISION_REQUIRED; grace expires with no decision -> REOPENED_BY_LAPSE and
         the rung's lapsed-track floor (BLOCKED at run). A decision after a lapse does not restore
         the original deadline; the lapse stays in the history.
      6  ANTI-LAUNDERING: new deadline = min(existing, re-score date + period). An upward re-score
         can bring a deadline earlier; nothing can extend one -- there is no function that does,
         and a downward re-score tries and fails. (Adversarial.)
      7  THE DAY-ONE COHORT IS CLOSED AT ESTABLISHMENT. Only identities in the ledger at the
         establishment commit may be members; one added later is refused. The cohort decision
         records an accepted, dated breach -- it resets no clock and never says compliant.
         (Adversarial.) A baseline with zero day-one breaches is flagged as either young or
         laundered.
      8  A TRACK WITH NO CLOSURES IS AMNESTY WITH PAPERWORK: zero verified closures in the
         configured period is TRACK_STALLED.
      9  EVERY NUMBER COMES FROM CONFIGURATION. A missing period or grace refuses.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

NUMBERS = {
    'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 180, 'LOW': 365},
    'breach_grace_days': {'CRITICAL': 0, 'HIGH': 7, 'MEDIUM': 14, 'LOW': 14},
    'track_stall_period_days': 90,
    'no_fix_recheck_days': 30,
    'severity_formula_version': 'severity-formula/1',
}
CLAIMABLE = {'run_id': '1', 'observed_at': '2026-01-10T00:00:00Z', 'observed_at_source': 'SIDECAR'}
UNCLAIMABLE = {'run_id': '1', 'observed_at': '2026-01-10T00:00:00Z', 'observed_at_source': 'FILE_MTIME'}


def main():
    try:
        import remediation_sla as sla
    except ImportError as exc:
        print('FAIL: no remediation SLA exists (%s). ETFB sections 6-8 are designed and not built: '
              'nothing derives a severity, establishes fix availability, starts a clock or lapses a '
              'track.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # 1  Severity.
    r = sla.derive_severity({'trivy': 'HIGH', 'osv': 'MEDIUM'}, NUMBERS, today='2026-10-14')
    check(r['effective_severity'] == 'HIGH' and r['scanner_disagreement'] is True,
          'two scanners disagreeing did not yield the highest with the disagreement recorded: %r' % r)
    check(r['scanner_severities'] == {'trivy': 'HIGH', 'osv': 'MEDIUM'}, 'scanner severities were not preserved')
    check(r['formula_version'] == 'severity-formula/1', 'no formula version on the derivation')
    r = sla.derive_severity({'trivy': 'HIGH'}, NUMBERS, today='2026-10-14', signals={'known_exploited': True})
    check(r['effective_severity'] == 'CRITICAL', 'a known-exploited HIGH did not raise under formula/1: %r' % r)
    r = sla.derive_severity({}, NUMBERS, today='2026-10-14')
    check(r['effective_severity'] is None, 'no scanner severity derived a severity from nothing')
    r = sla.derive_severity({'trivy': 'HIGH'}, dict(NUMBERS, severity_formula_version='severity-formula/9'),
                            today='2026-10-14')
    check(r['effective_severity'] is None and 'formula' in r['why'], 'an unknown formula version derived a severity')
    r = sla.derive_severity({'trivy': 'HIGH'}, NUMBERS, today='2026-10-14',
                            override={'value': 'CRITICAL', 'reason': 'exposed'})
    check(r['effective_severity'] == 'CRITICAL', 'an upward override was not free')
    r = sla.derive_severity({'trivy': 'HIGH'}, NUMBERS, today='2026-10-14',
                            override={'value': 'LOW', 'reason': 'noise'})
    check(r['effective_severity'] == 'HIGH' and r['override']['applied'] is False,
          'a downward override with no authority or expiry was applied: %r' % r)
    r = sla.derive_severity({'trivy': 'HIGH'}, NUMBERS, today='2026-10-14',
                            override={'value': 'LOW', 'reason': 'noise', 'authority': 'security-lead',
                                      'expires': '2099-01-01'})
    check(r['effective_severity'] == 'LOW' and r['override']['applied'] is True, 'an attributed downward override was refused')
    r = sla.derive_severity({'trivy': 'HIGH'}, NUMBERS, today='2026-10-14',
                            override={'value': 'LOW', 'reason': 'noise', 'authority': 'security-lead',
                                      'expires': '2020-01-01'})
    check(r['effective_severity'] == 'HIGH', 'an expired downward override still applied')

    # 2  Fix availability.
    for value, admits, closing in (('FIX_AVAILABLE', True, 'REMEDIATED'), ('MITIGATION_AVAILABLE', True, 'MITIGATED'),
                                   ('NO_FIX_AVAILABLE', False, None), ('FIX_AVAILABILITY_NOT_ESTABLISHED', False, None)):
        r = sla.fix_availability_admits(value, NUMBERS, established_on='2026-10-01', today='2026-10-14')
        check(r['admits_track'] is admits and r['closing_disposition'] == closing,
              '%s: admits=%r closes to %r' % (value, r['admits_track'], r['closing_disposition']))
    r = sla.fix_availability_admits('FIX_AVAILABILITY_NOT_ESTABLISHED', NUMBERS, established_on=None, today='2026-10-14')
    check(r['routes_to'] == 'DECISION_REQUIRED' and r['may_grandfather'] is False,
          'not-established fix availability did not route DECISION_REQUIRED or allowed grandfathering')
    r = sla.fix_availability_admits('NO_FIX_AVAILABLE', NUMBERS, established_on='2026-08-01', today='2026-10-14')
    check(r['routes_to'] == 'DECISION_REQUIRED' and r['recheck_due'] == '2026-08-31' and r['recheck_overdue'] is True,
          'NO_FIX_AVAILABLE did not carry an overdue re-check: %r' % r)
    r = sla.fix_availability_admits('FIX_AVAILABLE', {}, established_on='2026-10-01', today='2026-10-14')
    check(r['routes_to'] != 'POLICY_NUMBER_NOT_CONFIGURED', 'FIX_AVAILABLE needed a number it does not use')
    r = sla.fix_availability_admits('NO_FIX_AVAILABLE', {}, established_on='2026-10-01', today='2026-10-14')
    check(r['state'] == 'POLICY_NUMBER_NOT_CONFIGURED', 'a missing re-check cadence defaulted')
    try:
        sla.fix_availability_admits('probably-fixable', NUMBERS, established_on=None, today='2026-10-14')
        check(False, 'an unregistered fix availability was accepted')
    except ValueError:
        pass

    # 3  The clock.
    entry = {'first_seen': '2026-01-10', 'age_established': True, 'first_seen_provenance': CLAIMABLE,
             'effective_severity': 'HIGH'}
    r = sla.sla_deadline(entry, NUMBERS, established_on='2026-10-01')
    check(r['deadline'] == '2026-02-09' and r['clock_start_basis'] == 'first_seen',
          'a claimable first_seen did not start the clock: %r' % r)
    r = sla.sla_deadline(dict(entry, age_established=False), NUMBERS, established_on='2026-10-01')
    check(r['deadline'] == '2026-10-31' and r['clock_start_basis'] == 'baseline_establishment'
          and r['age_established'] is False and 'may be older' in r['why'],
          'an unestablished age did not start at establishment with the record saying so: %r' % r)
    # ADVERSARIAL: an age CLAIMED established from file mtime. Not a deadline from mtime, not from
    # establishment either -- the claim is wrong and the entry gets no deadline until it is fixed.
    r = sla.sla_deadline(dict(entry, first_seen_provenance=UNCLAIMABLE), NUMBERS, established_on='2026-10-01')
    check(r['deadline'] is None and r['clock_start_basis'] == 'unclaimable' and r['routes_to'] == 'DECISION_REQUIRED',
          'an established age from FILE_MTIME produced a deadline: %r' % r)
    r = sla.sla_deadline(dict(entry, effective_severity=None), NUMBERS, established_on='2026-10-01')
    check(r['deadline'] is None, 'no effective severity produced a deadline')
    r = sla.sla_deadline(entry, {'sla_period_days': {'CRITICAL': 7}}, established_on='2026-10-01')
    check(r['state'] == 'POLICY_NUMBER_NOT_CONFIGURED', 'a missing HIGH period defaulted')
    # 4  Breached on day one: a two-year-old critical does not get a fresh 7 days.
    old = {'first_seen': '2024-06-01', 'age_established': True, 'first_seen_provenance': CLAIMABLE,
           'effective_severity': 'CRITICAL'}
    r = sla.sla_deadline(old, NUMBERS, established_on='2026-10-01')
    check(r['deadline'] == '2024-06-08' and r['breached_at_establishment'] is True,
          'a two-year-old CRITICAL was not breached on day one: %r' % r)

    # 5  Breach staging.
    def track(deadline, today, severity='HIGH', decisions=(), fix='FIX_AVAILABLE', rung='run', **extra):
        e = {'effective_severity': severity, 'fix_availability': fix, 'sla_deadline': deadline,
             'scanner_reproduces': True, 'coverage_demonstrated': True}
        e.update(extra)
        return sla.track_state(e, list(decisions), NUMBERS, today=today, rung=rung)

    r = track('2026-10-20', '2026-10-14')
    check(r['state'] == 'ON_TRACK' and r['control_class'] == 'pre_existing_on_track'
          and r['routes_to'] == 'PROCEED_WITH_ADVISORY', 'an unexpired track did not proceed with advisory: %r' % r)
    r = track('2026-10-10', '2026-10-14')                       # HIGH: 7 days grace, inside it
    check(r['state'] == 'BREACHED_UNDECIDED' and r['routes_to'] == 'DECISION_REQUIRED' and r['classification'] is None,
          'a breach inside grace did not route DECISION_REQUIRED: %r' % r)
    r = track('2026-10-01', '2026-10-14')                       # past deadline + grace
    check(r['state'] == 'BREACHED_UNDECIDED' and r['classification'] == 'REOPENED_BY_LAPSE'
          and r['control_class'] == 'pre_existing_track_lapsed' and r['routes_to'] == 'BLOCKED',
          'grace expired with no decision did not lapse to BLOCKED at run: %r' % r)
    r = track('2026-10-01', '2026-10-14', rung='walk')
    check(r['routes_to'] == 'DECISION_REQUIRED', 'a lapsed track at walk did not take walk\'s floor')
    r = track('2026-10-13', '2026-10-14', severity='CRITICAL')  # CRITICAL: no grace
    check(r['classification'] == 'REOPENED_BY_LAPSE', 'a breached CRITICAL got grace it is not configured to have')
    dec = {'kind': 'accepted_risk', 'date': '2026-10-05', 'authority': 'security-lead', 'expires': '2026-11-01'}
    r = track('2026-10-01', '2026-10-14', decisions=[dec])
    check(r['state'] == 'BREACHED_ACCEPTED' and r['routes_to'] == 'PROCEED_WITH_ADVISORY'
          and r['deadline'] == '2026-10-01' and 'breached' in r['record'] and 'compliant' not in r['record'],
          'an accepted breach misrecorded: %r' % r)
    # A decision after a lapse: a new dated decision, the original deadline not restored, lapse kept.
    late = {'kind': 'accepted_risk', 'date': '2026-10-12', 'authority': 'security-lead', 'expires': '2026-11-01'}
    r = track('2026-10-01', '2026-10-14', decisions=[late])
    check(r['state'] == 'BREACHED_ACCEPTED' and r['deadline'] == '2026-10-01' and r['lapses'],
          'a decision after a lapse restored the deadline or erased the lapse: %r' % r)
    expired = {'kind': 'accepted_risk', 'date': '2026-10-05', 'authority': 'security-lead', 'expires': '2026-10-10'}
    r = track('2026-10-01', '2026-10-14', decisions=[expired])
    check(r['classification'] == 'REOPENED_BY_LAPSE' and r['routes_to'] == 'BLOCKED',
          'an expired acceptance did not lapse; silence renewed it: %r' % r)
    nobody = {'kind': 'accepted_risk', 'date': '2026-10-05', 'expires': '2026-11-01'}
    r = track('2026-10-01', '2026-10-14', decisions=[nobody])
    check(r['state'] != 'BREACHED_ACCEPTED', 'a decision with no authority accepted a breach')
    r = track('2026-10-20', '2026-10-14', fix='FIX_AVAILABILITY_NOT_ESTABLISHED')
    check(r['state'] == 'TRACK_NOT_ADMITTED' and r['routes_to'] == 'DECISION_REQUIRED',
          'unestablished fix availability took a track: %r' % r)
    r = track('2026-10-20', '2026-10-14', fix='NO_FIX_AVAILABLE')
    check(r['state'] == 'TRACK_NOT_ADMITTED' and r['routes_to'] == 'DECISION_REQUIRED',
          'NO_FIX_AVAILABLE took a track instead of owing a decision: %r' % r)
    r = track('2026-10-01', '2026-10-14', fix='NO_FIX_AVAILABLE', decisions=[dec])
    check(r['state'] == 'BREACHED_ACCEPTED' and r['routes_to'] == 'PROCEED_WITH_ADVISORY',
          'NO_FIX_AVAILABLE with an unexpired acceptance did not proceed with advisory')
    r = track('2026-10-20', '2026-10-14', scanner_reproduces=False, coverage_demonstrated=True)
    check(r['state'] == 'CLOSED_VERIFIED', 'the scanner not reproducing over demonstrated coverage did not close')
    r = track('2026-10-20', '2026-10-14', scanner_reproduces=False, coverage_demonstrated=False)
    check(r['state'] != 'CLOSED_VERIFIED' and r['classification'] == 'POTENTIALLY_ABSENT',
          'absence without coverage was called fixed: %r' % r)
    r = track('2026-10-20', '2026-10-14', ticket_closed=True)
    check(r['state'] == 'ON_TRACK', 'closing a ticket cleared a finding')
    r = sla.track_state({'effective_severity': 'HIGH', 'fix_availability': 'FIX_AVAILABLE', 'sla_deadline': '2026-10-01',
                         'scanner_reproduces': True, 'coverage_demonstrated': True}, [],
                        {'sla_period_days': NUMBERS['sla_period_days']}, today='2026-10-14', rung='run')
    check(r['state'] == 'POLICY_NUMBER_NOT_CONFIGURED', 'a missing grace defaulted')

    # 6  Anti-laundering.
    check(not hasattr(sla, 'extend_deadline') and not hasattr(sla, 'set_deadline'),
          'a function exists that can extend or set a deadline; a bot that can extend an expiry can grant amnesty')
    r = sla.rescore_deadline('2026-02-09', '2026-02-01', 'CRITICAL', NUMBERS)
    check(r['deadline'] == '2026-02-08' and r['moved'] == 'earlier', 'an upward re-score did not bring the deadline earlier')
    # ADVERSARIAL: re-score down to LOW to buy a year.
    r = sla.rescore_deadline('2026-02-09', '2026-02-01', 'LOW', NUMBERS)
    check(r['deadline'] == '2026-02-09' and r['moved'] == 'unchanged' and r['attempted'] == '2027-02-01',
          'a downward re-score extended the deadline: %r' % r)
    r = sla.rescore_deadline(None, '2026-02-01', 'HIGH', NUMBERS)
    check(r['deadline'] == '2026-03-03', 'a first deadline from a re-score was wrong: %r' % r)
    r = sla.rescore_deadline('2026-02-09', '2026-02-01', 'HIGH', {})
    check(r['state'] == 'POLICY_NUMBER_NOT_CONFIGURED', 'a re-score with no period defaulted')

    # 7  The day-one cohort.
    at_establishment = [
        {'identity': 'a', 'environment': 'prod', 'effective_severity': 'CRITICAL', 'sla_deadline': '2024-06-08'},
        {'identity': 'b', 'environment': 'prod', 'effective_severity': 'HIGH', 'sla_deadline': '2025-01-01'},
        {'identity': 'c', 'environment': 'prod', 'effective_severity': 'LOW', 'sla_deadline': '2027-01-01'},
    ]
    decision = {'decided_on': '2026-10-01', 'authority': 'ciso', 'establishment_commit': 'e' * 40,
                'burn_down': {'CRITICAL': '2026-11-01', 'HIGH': '2026-12-01', 'MEDIUM': '2027-03-01', 'LOW': '2027-06-01'},
                'members': ['a', 'b', 'c', 'd']}
    r = sla.day_one_cohort(at_establishment, decision, NUMBERS, today='2026-10-14')
    check(sorted(r['members']) == ['a', 'b'], 'cohort members are %r, expected a and b (breached at establishment)' % r['members'])
    # ADVERSARIAL: d was not in the ledger at establishment -- added later, refused.
    check(any(x['identity'] == 'd' for x in r['refused']), 'an identity absent at establishment joined the cohort')
    check(any(x['identity'] == 'c' for x in r['refused']), 'an unbreached entry was accepted into the breach cohort')
    check(r['resets_clock'] is False and all(m['sla_deadline'] == e['sla_deadline'] for m, e in
                                             zip(sorted(r['member_records'], key=lambda m: m['identity']), at_establishment[:2])),
          'the cohort decision reset a clock')
    ms = {m['identity']: m for m in r['member_records']}
    check(ms['a']['state'] == 'BREACHED_ACCEPTED' and ms['a']['accepted_until'] == '2026-11-01'
          and 'breached' in ms['a']['record'] and 'compliant' not in ms['a']['record'],
          'a cohort member is not recorded as an accepted, dated breach: %r' % ms['a'])
    r2 = sla.day_one_cohort(at_establishment, decision, NUMBERS, today='2026-11-02')
    ms2 = {m['identity']: m for m in r2['member_records']}
    check(ms2['a']['state'] == 'BREACHED_UNDECIDED' and ms2['a']['classification'] == 'REOPENED_BY_LAPSE',
          'a cohort member past its burn-down sub-deadline did not lapse: %r' % ms2['a'])
    check(ms2['b']['state'] == 'BREACHED_ACCEPTED', 'a HIGH member lapsed before its own sub-deadline')
    bad = dict(decision, burn_down={'CRITICAL': '2026-11-01'})
    r = sla.day_one_cohort(at_establishment, bad, NUMBERS, today='2026-10-14')
    check(any(x['identity'] == 'b' for x in r['refused']), 'a member with no burn-down date for its severity was accepted')
    r = sla.day_one_cohort(at_establishment, dict(decision, authority=''), NUMBERS, today='2026-10-14')
    check(r['members'] == [] and r['refused'], 'a cohort decision with no authority admitted members')
    s = sla.baseline_sanity(at_establishment, today='2026-10-14')
    check(s['day_one_breaches'] == 2 and s['suspicious'] is False, 'baseline sanity miscounted: %r' % s)
    s = sla.baseline_sanity([at_establishment[2]], today='2026-10-14')
    check(s['suspicious'] is True and 'laundered' in s['why'], 'zero day-one breaches was not flagged: %r' % s)

    # 8  A track with no closures.
    r = sla.track_stalled(['2026-05-01'], NUMBERS, today='2026-10-14')
    check(r['state'] == 'TRACK_STALLED' and r['routes_to'] == 'DECISION_REQUIRED',
          'no closure in 90 days was not TRACK_STALLED: %r' % r)
    r = sla.track_stalled(['2026-09-01'], NUMBERS, today='2026-10-14')
    check(r['state'] != 'TRACK_STALLED', 'a recent closure read as stalled')
    r = sla.track_stalled([], {}, today='2026-10-14')
    check(r['state'] == 'POLICY_NUMBER_NOT_CONFIGURED', 'a missing stall period defaulted')

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: severity is the highest with disagreement recorded under a versioned formula and a '
          'downward override needs authority and expiry; only an established fix or mitigation admits '
          'a track; the clock starts at a claimable first_seen or at establishment with the age '
          'unestablished, and an mtime-dated age gets no deadline; a two-year-old CRITICAL is breached '
          'on day one; breach stages to DECISION_REQUIRED, through the configured grace, to '
          'REOPENED_BY_LAPSE at the rung\'s lapsed floor; nothing extends a deadline; the cohort is '
          'closed at establishment and records breached, never compliant; a track with no closures is '
          'stalled; every number is configuration.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
