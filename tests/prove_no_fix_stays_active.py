#!/usr/bin/env python3
"""NO_FIX_AVAILABLE never becomes CLEARED, FIXED, FALSE_POSITIVE, resolved or closed (review round 2).

WHY THIS FILE EXISTS

    The owner's no-vendor-fix policy (relayed 2026-11-09 in the round-2 review findings; the kit's
    term is NO_FIX_AVAILABLE): the disposition engine must never translate "upstream has no fix"
    into CLEARED, FIXED or FALSE_POSITIVE. The vulnerability stays ACTIVE; an exception changes
    its TREATMENT, not its existence. An expired exception returns to review.

    Each consumer is checked where it decides. Where the code already guarded, the guard is named
    (file:function) in the case's docstring and a named mutant of that guard must turn the case red.

WHAT IT PROVES
  DISPOSITION ENGINE (scripts/remediation_sla.py)
    D1  fix_availability_admits(NO_FIX_AVAILABLE): no track, no closing disposition (never
        REMEDIATED, never FALSE_POSITIVE), routes DECISION_REQUIRED
    D2  track_state, the scanner still reproducing, no decision: TRACK_NOT_ADMITTED +
        DECISION_REQUIRED -- never CLOSED_VERIFIED, and a closed ticket changes nothing
    D3  an EXPIRED acceptance on it: back to DECISION_REQUIRED (review), still not closed
    D4  an in-force acceptance changes the treatment (BREACHED_ACCEPTED / ON_TRACK), never the
        existence (never CLOSED_VERIFIED)
  REPORT (scripts/scan_report.py), from Trivy SARIF with no fixed version
    R1  the no-fix finding is counted and blocking; no basis, no false-positive
    R2  an EXPIRED accepted-risk decision on it does not suppress: still blocking, shown EXPIRED
    R3  an in-date accepted-risk decision suppresses (treatment) but the finding stays in the
        findings file (disposition_basis durable) -- it still exists
  TICKETS (scripts/reconcile_tickets.py, through the Jira stand-in)
    T1  a no-fix ticket through re-check, review and advisory cycles is never closed, resolved or
        relabelled fixed / false positive; only clock notes are added
    T2  the no-fix EXEMPTION expiring returns the ticket to REVIEW (a named, once-only note and
        label) while it stays open
    T3  the reconciler never clears a ticket whose finding is still reported
  EXPORT (scripts/evidence_export.py)
    E1  the exported findings section keeps the no-fix finding, counts it, and carries no closed /
        resolved / false-positive word for it; its disposition basis is kept
  MUTANTS (each must be caught)
    no-fix-counts-as-cleared       remediation_sla admits NO_FIX_AVAILABLE as a fix track closing REMEDIATED
    expired-exception-suppresses   scan_report.not_suppressed_because ignores an expiry
    expired-exemption-stays-exempt the no-fix clock never reads the exemption's end

EXIT  0 all hold   1 a case failed (named)   2 could not be checked
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

NO_FIX = 'NO_FIX_AVAILABLE'
# Words a no-fix finding or its ticket must never be turned into.
NEVER = ('CLEARED', 'CLOSED_VERIFIED', 'FIXED', 'FALSE_POSITIVE', 'REMEDIATED', 'RESOLVED')
NUMBERS = {'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 180, 'LOW': 365},
           'breach_grace_days': {'CRITICAL': 0, 'HIGH': 7, 'MEDIUM': 14, 'LOW': 14},
           'severity_formula_version': 'severity-formula/1', 'no_fix_recheck_days': 30,
           'track_stall_period_days': 90}
TODAY = datetime.date(2026, 11, 9)


# ── the disposition engine ───────────────────────────────────────────────────────────────

def engine(sla, fails):
    """D1-D4. Guards: scripts/remediation_sla.py fix_availability_admits (the NO_FIX_AVAILABLE
    branch: admits_track False, closing_disposition None, routes_to DECISION_REQUIRED) and
    track_state (the admission guard `if not fa['admits_track'] and not in_force` -> TRACK_NOT_ADMITTED;
    closure only on `scanner_reproduces is False` over demonstrated coverage; `ticket_closed` ignored)."""
    fa = sla.fix_availability_admits(NO_FIX, NUMBERS, '2026-11-01', '2026-11-09')
    if fa['admits_track'] or fa['closing_disposition'] is not None or fa['routes_to'] != sla.DECISION_REQUIRED:
        fails.append('D1: NO_FIX_AVAILABLE was admitted or given a closing disposition: %r' % fa)

    def track(decisions=(), **extra):
        e = {'effective_severity': 'HIGH', 'fix_availability': NO_FIX, 'sla_deadline': '2026-10-01',
             'fix_availability_established_on': '2026-11-01', 'scanner_reproduces': True,
             'coverage_demonstrated': True}
        e.update(extra)
        return sla.track_state(e, list(decisions), NUMBERS, today='2026-11-09', rung='run')

    for label, r in (('D2', track()), ('D2 ticket closed', track(ticket_closed=True))):
        if r['state'] != sla.TRACK_NOT_ADMITTED or r['routes_to'] != sla.DECISION_REQUIRED:
            fails.append('%s: a reproducing no-fix finding was %s / %s, expected TRACK_NOT_ADMITTED + '
                         'DECISION_REQUIRED' % (label, r['state'], r['routes_to']))
        if r['state'] in NEVER:
            fails.append('%s: a reproducing no-fix finding was turned into %s' % (label, r['state']))
    expired = {'kind': 'accepted_risk', 'date': '2026-10-05', 'authority': 'security-lead', 'expires': '2026-11-01'}
    r = track([expired])
    if r['state'] != sla.TRACK_NOT_ADMITTED or r['routes_to'] != sla.DECISION_REQUIRED or r['state'] in NEVER:
        fails.append('D3: an EXPIRED acceptance on a no-fix finding did not return it to review '
                     '(DECISION_REQUIRED): %s / %s' % (r['state'], r['routes_to']))
    if not any('expired' in d['why'] for d in r['decisions']):
        fails.append('D3: the expired acceptance is not named as expired: %r' % r['decisions'])
    live = dict(expired, expires='2027-01-01')
    r = track([live])
    if r['state'] not in (sla.BREACHED_ACCEPTED, sla.ON_TRACK) or r['state'] in NEVER:
        fails.append('D4: an in-force acceptance on a no-fix finding was %s, expected its treatment '
                     '(BREACHED_ACCEPTED or ON_TRACK), never a closure' % r['state'])


# ── the report ───────────────────────────────────────────────────────────────────────────

def _nofix_doc():
    """A Trivy dependency finding with NO fixed version (the vendor has no fix)."""
    from prove_identity_durability import dep_sarif
    doc = dep_sarif('0.50.1', 'libfoo 1.2: heap overflow, no fixed version upstream', 'CVE-2026-40001',
                    purl='pkg:pypi/libfoo@1.2')
    props = doc['runs'][0]['results'][0]['properties']
    props.pop('fixed_version', None)
    props['fix_status'] = NO_FIX
    return doc


def _disp(key, expires):
    return {'schema_version': 1, 'fingerprint': key, 'scanner': 'trivy', 'rule': 'CVE-2026-40001',
            'scope_path': 'requirements.txt', 'disposition_type': 'ACCEPTED_RISK',
            'rationale': 'No upstream fix; exposure limited to the batch worker (change-record-9).',
            'evidence_ref': 'change-record-9', 'approver_role': 'security-lead',
            'created': '2026-09-01', 'expires': expires, 'state': 'approved', 'ticket': 'SEC-90'}


def _parse(sr, work):
    p = os.path.join(work, 'nofix.sarif')
    with io.open(p, 'w', encoding='utf-8') as fh:
        json.dump(_nofix_doc(), fh)
    findings, state, _ex = sr.parse_sarif(p, 'trivy')
    if state != 'COMPLETE' or len(findings) != 1 or not findings[0].get('identity'):
        raise RuntimeError('fixture: parse_state=%s, %d finding(s)' % (state, len(findings)))
    return findings[0]


def _render(sr, f, reg):
    cfg = dict(scanner='trivy', applicability='APPLICABLE', execution='COMPLETE', scope='.',
               artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=10)
    return sr.render(cfg, [f], 'COMPLETE', reg, 'LOADED', (sr.EXAMINED, []), TODAY)


def report(sr, work, fails):
    """R1-R3. Guards: scripts/scan_report.py is_suppressed (a record suppresses only when
    not_suppressed_because is empty) and not_suppressed_because (`EXPIRED <date>` when the expiry
    is past); blocking_of lists every unsuppressed finding; nothing in parse_sarif or
    disposition_for reads fix status, so no-fix cannot become a disposition."""
    f = _parse(sr, work)
    ident = f['identity']
    blocking = sr.blocking_of([f], {}, TODAY)
    rec, basis, _note = sr.disposition_for(f, {}, TODAY)
    if len(blocking) != 1 or rec is not None or basis:
        fails.append('R1: the no-fix finding is not counted active and undecided (blocking %d, basis %r)'
                     % (len(blocking), basis))
    reg = {ident: _disp(ident, '2026-10-31')}
    if sr.is_suppressed(f, reg, TODAY) or len(sr.blocking_of([f], reg, TODAY)) != 1:
        fails.append('R2: an EXPIRED accepted risk on a no-fix finding suppressed it (it must return to '
                     'review while active)')
    why = sr.not_suppressed_because(reg[ident], TODAY)
    if 'EXPIRED' not in why:
        fails.append('R2: the expiry is not named: %r' % why)
    text = _render(sr, f, reg)
    if isinstance(text, tuple):
        text = text[0]
    if 'EXPIRED' not in str(text):
        fails.append('R2: the report does not show the decision EXPIRED')
    for w in ('FALSE_POSITIVE', 'REMEDIATED'):
        if w in str(text):
            fails.append('R2: the report calls the no-fix finding %s' % w)
    live = {ident: _disp(ident, '2099-01-01')}
    if not sr.is_suppressed(f, live, TODAY):
        fails.append('R3: an in-date accepted risk did not change the treatment (suppress)')
    o = sr.observation_of(f, 'sca', True, disposition_basis=sr.disposition_for(f, live, TODAY)[1])
    if o.get('identity') != ident or o.get('disposition_basis') != 'durable' or o.get('state') != 'FINGERPRINTED':
        fails.append('R3: an accepted no-fix finding did not stay in the findings file as itself: %r'
                     % dict((k, o.get(k)) for k in ('identity', 'disposition_basis', 'state')))
    return f, o


# ── the tickets ──────────────────────────────────────────────────────────────────────────

def _labels_of(w, ref):
    return list(w.t.issues[ref]['fields'].get('labels') or [])


def _status_key(w, ref):
    return ((w.t.issues[ref]['fields'].get('status') or {}).get('statusCategory') or {}).get('key')


def tickets(fails, tmp):
    """T1-T2. Guards: scripts/reconcile_tickets.py recheck_pass ("Nothing is closed, reopened or
    exempted further"; it only comments and labels, and the mutation is ticket.recheck_due,
    ROUTINE_RECONCILIATION, which ticket_model classifies as exempting nothing); the exemption's end
    is read from the ticket (block_facts 'exempt until') and returns the ticket to review once."""
    import prove_ticket_templates as ptt
    mods = ptt.imports()
    if mods is None:
        fails.append('T: the ticket machinery did not import')
        return
    ka, ks, rt, tb, ps, tt, fc = mods
    w = ptt.W(mods, tmp)
    nf = tt.example_finding(fix_status=NO_FIX)
    p = w.finalize('USR-NOFIX-71', {'template': 'nofix-recheck', 'template_version': 2,
                                    'items': [{'finding': nf, 'vendor': 'Contoso', 'requested_by': 'app-team',
                                               'evidence': nf['evidence'], 'recheck_days': 30,
                                               'exemption_days': 7}]})
    res, _s = w.submit(p, 'nofix-0071')
    it = ptt.items_of(res)
    ref = (it or [{}])[0].get('ref')
    if not ref or 'secure-cicd-kit-nofix' not in _labels_of(w, ref):
        fails.append('T1: the no-fix ticket was not created (%r)' % (it,))
        return
    body = tb.adf_text(w.t.issues[ref].get('description'))
    if '2026-11-10' not in body:
        fails.append('T2: PRECONDITION -- the ticket does not state its exemption end 2026-11-10')
    ledger, backend = {}, rt.choose_backend(tb.JIRA_ENV)[0]
    # Day 2026-11-12: the 7-day exemption ended on the 10th; the 30-day re-check is not due.
    rt.resurface(ledger, backend, True, '2026-11-12')
    exp = [c for i, c in w.t.comments if i == ref and 'EXEMPTION EXPIRED' in c]
    if len(exp) != 1 or 'secure-cicd-kit-nofix-exemption-expired' not in _labels_of(w, ref):
        fails.append('T2: the expired no-fix exemption did not return the ticket to review (%d note(s), '
                     'labels %r)' % (len(exp), _labels_of(w, ref)))
    for day in ('2026-11-13', '2026-12-05', '2027-02-05', '2027-08-01', '2028-01-01'):
        rt.resurface(ledger, backend, True, day)
    exp = [c for i, c in w.t.comments if i == ref and 'EXEMPTION EXPIRED' in c]
    if len(exp) > 1:
        fails.append('T2: the exemption-expired note was raised %d times, expected once' % len(exp))
    if _status_key(w, ref) == 'done':
        fails.append('T1: the no-fix ticket was CLOSED by the clock')
    bad = [l for l in _labels_of(w, ref) if any(x in l.upper().replace('-', '_') for x in
                                                ('FALSE_POSITIVE', 'REMEDIATED', 'FIXED', 'RESOLVED', 'CLEARED'))]
    if bad:
        fails.append('T1: the no-fix ticket was labelled %r' % bad)
    notes = [c for i, c in w.t.comments if i == ref]
    for c in notes:
        if 'RESOLVED - PENDING VERIFICATION' in c or 'verified absent' in c.lower():
            fails.append('T1: the clock wrote a resolution or clearance on the no-fix ticket: %s' % c[:120])
    want = ('RE-CHECK DUE', 'NO-FIX REVIEW DUE', 'NO-FIX ADVISORY')
    if not all(any(x in c for c in notes) for x in want):
        fails.append('T1: PRECONDITION -- the clock did not run every cycle (%r)'
                     % [x for x in want if not any(x in c for c in notes)])


def tickets_reported(fails):
    """T3. Guard: scripts/reconcile_tickets.py clearance_pass skips an entry whose cluster is observed
    this run, or any of whose members is present (`key in observed`, `any(i in present ...)`)."""
    import reconcile_tickets as rt
    obs = {'scanner': 'trivy', 'tool': 'trivy', 'rule_id': 'CVE-2026-40001', 'severity': 'high',
           'canonical_path': 'requirements.txt', 'line': 7, 'finding_subject': 'SOURCE_DEPENDENCY',
           'state': 'FINGERPRINTED', 'identity': 'n' * 64, 'what': 'w' * 64, 'where': 'pkg:pypi/libfoo@1.2',
           'content': 'c' * 64, 'what_aliases': ['CVE-2026-40001'], 'fp': 'f' * 16, 'job': 'sca',
           'row_established': True}
    cov = {'trivy': {'established': True, 'gate': 'FAIL', 'execution': 'COMPLETE', 'scope': '.',
                     'scanner_version': '0.50.1'}}
    be, ledger = rt.RecordingBackend(), {}
    with contextlib.redirect_stderr(io.StringIO()):
        rt.reconcile(*rt.build_clusters([obs]), be, ledger, True, today='2026-11-01', context={'coverage': cov})
        res = rt.reconcile(*rt.build_clusters([obs]), be, ledger, True, today='2026-12-01',
                           context={'coverage': cov})
    if be.closed or res.get('cleared') or res['outcomes'].get('LEDGER_BOUND') != 1:
        fails.append('T3: a still-reported no-fix finding\'s ticket was cleared or not kept (closed %r, '
                     'cleared %r, %r)' % (be.closed, res.get('cleared'), res['outcomes']))


# ── the export ───────────────────────────────────────────────────────────────────────────

def export(obs, fails):
    """E1. Guard: scripts/evidence_export.py assemble projects each findings.json row through FINDING
    (_pick) and counts every row; it adds no state of its own."""
    import evidence_export as ee
    raw = {'security_records': [], 'findings': [({'run_id': 7, 'name': 'security-report-trivy'}, [obs])],
           'review_signals': [], 'promotions': [], 'deployments': [], 'outboxes': [], 'drained': [],
           'sbom_digest': None, 'commit': None, 'reads': {}, 'expired': []}
    d = ee.assemble('o/r', 'c' * 40, {'kind': 'commit', 'ref': 'c' * 40}, raw)
    sec = (d.get('sections') or d).get('findings') if isinstance(d, dict) else None
    if not isinstance(sec, dict) or sec.get('count') != 1:
        fails.append('E1: the export does not count the no-fix finding: %r' % (sec,))
        return
    g = sec['findings'][0]
    if g.get('identity') != obs['identity'] or g.get('disposition_basis') != obs.get('disposition_basis'):
        fails.append('E1: the exported finding lost its identity or disposition basis: %r' % g)
    blob = json.dumps(g)
    for w in ('FALSE_POSITIVE', 'REMEDIATED', 'CLOSED', 'RESOLVED', 'CLEARED', 'FIXED'):
        if w in blob.upper().replace('-', '_') and w not in obs.get('rule_id', ''):
            fails.append('E1: the exported no-fix finding carries %s: %s' % (w, blob[:300]))


# ── wiring ───────────────────────────────────────────────────────────────────────────────

def run_all(quiet=False):
    import remediation_sla as sla
    import scan_report as sr
    fails = []
    work = tempfile.mkdtemp(prefix='no-fix-')
    try:
        steps = (('D1-D4 disposition engine', lambda: engine(sla, fails)),
                 ('R1-R3 report', lambda: _keep(report(sr, work, fails))),
                 ('T1-T2 tickets: clock, expired exemption', lambda: tickets(fails, _sub(work, 't'))),
                 ('T3 tickets: reported finding never cleared', lambda: tickets_reported(fails)),
                 ('E1 export', lambda: export(_KEPT['obs'], fails) if _KEPT.get('obs') else
                  fails.append('E1: no observation (R failed)')))
        for label, fn in steps:
            before = len(fails)
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    if quiet:
                        with contextlib.redirect_stdout(io.StringIO()):
                            fn()
                    else:
                        fn()
            except Exception as exc:                          # noqa: BLE001 - a crash is a failure
                fails.append('%s crashed: %s: %s' % (label, type(exc).__name__, exc))
            if not quiet:
                print('  %-46s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return fails


_KEPT = {}


def _keep(pair):
    _KEPT['obs'] = pair[1] if pair else None


def _sub(work, name):
    d = os.path.join(work, name)
    for sub in ('a', 'b', 'c', 'd'):
        os.makedirs(os.path.join(d, sub))
    return d


def mutants():
    import remediation_sla as sla
    import scan_report as sr
    import reconcile_tickets as rt
    survived = []

    def attempt(name, target, attr, replacement):
        original = getattr(target, attr)
        setattr(target, attr, replacement(original))
        try:
            caught = bool(run_all(quiet=True))
        finally:
            setattr(target, attr, original)
        print('  mutant %-32s %s' % (name, 'caught' if caught else 'SURVIVED'))
        if not caught:
            survived.append(name)

    def counts_as_cleared(orig):
        def f(value, numbers, established_on=None, today=None):
            out = orig(value, numbers, established_on=established_on, today=today)
            if value == sla.NO_FIX_AVAILABLE:
                out = dict(out, admits_track=True, track_kind='fix', closing_disposition=sla.REMEDIATED,
                           routes_to=None)
            return out
        return f
    attempt('no-fix-counts-as-cleared', sla, 'fix_availability_admits', counts_as_cleared)
    attempt('expired-exception-suppresses', sr, 'not_suppressed_because',
            lambda orig: (lambda d, today=None: '' if 'EXPIRED' in (orig(d, today) or '') else orig(d, today)))
    if hasattr(rt, 'nofix_exemption_expired'):
        attempt('expired-exemption-stays-exempt', rt, 'nofix_exemption_expired',
                lambda orig: (lambda *a, **kw: False))
    else:
        survived.append('expired-exemption-stays-exempt (rt.nofix_exemption_expired absent)')
    return survived


def main():
    print('=== NO_FIX_AVAILABLE stays ACTIVE: engine, report, tickets, export ===')
    fails = run_all()
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=No-fix policy unproven::%d failure(s)' % len(fails))
        return 1
    survived = mutants()
    if survived:
        print('::error title=No-fix mutants survived::%s' % ', '.join(survived))
        return 1
    print('no-fix policy proven: NO_FIX_AVAILABLE is never CLEARED, FIXED, FALSE_POSITIVE, resolved or '
          'closed by the disposition engine, the report, the ticket clock or reconciler, or the export; it '
          'stays active in every count; an expired acceptance or no-fix exemption returns it to review while '
          'it stays active; mutants caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
