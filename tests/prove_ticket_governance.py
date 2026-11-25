#!/usr/bin/env python3
"""Ticket governance (KDEC-043 PROPOSED): the full key is the identity, via is a claim, area-unresolved is a triage
state, and a multicloud finding is one identity with child obligations. NO NETWORK: the trackers are the Jira
stand-in of tests/prove_ticket_backends.py; Freshservice has its own proof (tests/prove_freshservice_tracker.py).

CASES (each the allowed path AND its refusal, docs/PROOF_RULE.md)
    G1  the correlation key: a label hit whose ticket carries the full key is exact (positive); a label hit on a
        ticket whose full key is ANOTHER key is a collision, and one with no full key is unverified -- both go to
        a person, never exact (negative); the short label is deterministic and two long labels that share their
        first 50 characters get different short forms (the old cut gave them one)
    G2  via provenance through tickets.submit: the claim, the authenticated identity and the tracker's creator agree
        -> PROVENANCE_ESTABLISHED (positive); the claim registered as another identity -> PROVENANCE_MISMATCH,
        labelled, alerted (negative); the creator unreadable -> PROVENANCE_NOT_ESTABLISHED, labelled unverified
    G3  area-unresolved: routing configured and nothing matching -> created with the area labels, an owner role and
        a deadline; before the deadline it is listed, not owed (positive); past it, AREA_UNRESOLVED_OVERDUE is a
        decision owed and the run exits 1 (negative); a later rule resolves it (positive); with no routing at all
        the kit default is the area (positive)
    G4  multicloud: one parent, one child per cloud asset with its own owner role (positive); one cloud only is
        refused (negative); the parent's verification while a child is open is CHILD_OBLIGATION_OPEN (negative);
        a fixer verifying their own child stays pending (negative); each child verified by another person ->
        the parent closes itself (positive)
    M   named mutants: M1 a label hit trusted without the key, M2 via trusted without the comparison, M3 an
        overdue area left silent, M4 a parent closing with a child open -- each must make its case fail

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

FAILS = []
P = 'secure-cicd-kit'
AWS = {'scheme': 'aws-resource', 'account_id': '123456789012', 'region': 'us-east-1',
       'arn': 'arn:aws:s3:::kit-proof-bucket'}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def g1(ctx, tmp):
    import ticket_intake as ti
    import ticket_governance as tg
    import reconcile_tickets as rt
    ck, other = 'd' * 32, 'e' * 32
    lab = tg.ck_label(P, ck)
    rec = {'correlation_key': ck, 'rule': 'R-1', 'aliases': [], 'asset_needle': '', 'title': ''}
    tickets = [{'ref': '1', 'labels': [lab], 'summary': '', '_text': '%s %s' % (tg.LINK_PREFIX, ck)},
               {'ref': '2', 'labels': [lab], 'summary': '', '_text': '%s %s' % (tg.STAMP_PREFIX, other)},
               {'ref': '3', 'labels': [lab], 'summary': '', '_text': 'nothing governed here'},
               {'ref': '4', 'labels': [], 'summary': 'R-1', 'stamp': other, '_text': 'R-1 again'}]
    m = ti.match(rec, tickets, lab, tg.STAMP_PREFIX, 85)
    cands = dict((t['ref'], b) for t, b, _s in m['candidates'])
    check([t['ref'] for t, _b in m['exact']] == ['1'], 'G1 the ticket carrying the full key was not the one exact: %r'
          % [(t['ref'], b) for t, b in m['exact']])
    check(cands == {'2': 'correlation-label-collision', '3': 'correlation-label-unverified'},
          'G1 a collision or an unverified label was not sent to a person: %r' % cands)
    a, b = 'x' * 52 + 'AAAAAAAAAA', 'x' * 52 + 'BBBBBBBBBB'
    sa, sb = rt.fit_label(a), rt.fit_label(b)
    check(len(sa) == 50 and len(sb) == 50 and sa != sb and rt.fit_label(a) == sa and a[:50] == b[:50],
          'G1 two long labels sharing 50 characters share a short form, or the form is not stable: %r %r' % (sa, sb))
    check(rt.fit_label('short-label') == 'short-label', 'G1 a label within the limit was changed')


def _v(ctx, tmp, **kw):
    return ctx['v2'].V(ctx['pt'], ctx['mods'], tmp, **kw)


def _creator(v, who):
    """The Jira stand-in records who created each issue: `who` (None: the read fails)."""
    def handler(rec):
        if who is None:
            return 500, {'errorMessages': ['internal']}, {}
        return 200, {'id': '1', 'fields': {'creator': {'accountId': who}}}, {}
    v.x.replay.on('GET', r'/rest/api/3/issue/\d+\?fields=creator$', handler)


def g2(ctx, tmp):
    import ticket_governance as tg
    v2, tt = ctx['v2'], ctx['mods'][5]
    for label, mapped, creator, want, mark in (
            ('the claim, the credential and the creator agree', 'stub', 'stub', tg.PROVENANCE_ESTABLISHED, None),
            ('the claim is registered as another identity', 'someone-else', 'stub', tg.PROVENANCE_MISMATCH,
             'provenance-mismatch'),
            ('the creator cannot be read', 'stub', None, tg.PROVENANCE_NOT_ESTABLISHED, 'provenance-unverified')):
        d = tempfile.mkdtemp(dir=tmp)
        v = _v(ctx, d)
        v.x.w.env['KIT_INTEGRATION_IDENTITIES'] = 'tines=%s' % mapped
        _creator(v, creator)
        res = v.submit(dict(v2.fparams(tt, v2.F(tt)), via='tines'))
        it = (v2.items(res) or [{}])[0]
        prov = it.get('provenance') or {}
        ref = it.get('ref')
        labels = v.labels(ref) if ref else []
        check(prov.get('state') == want and '%s-via-tines' % P in labels and
              (mark is None or '%s-%s' % (P, mark) in labels) and
              (mark is None or any(want in a for a in (res.get('data') or {}).get('alerts') or [])),
              'G2 %s: provenance %r, labels %r' % (label, prov, labels))


def _reconcile(rt, b, ledger, routing, today, records):
    clusters, withheld = rt.build_clusters(records)
    return rt.reconcile(clusters, withheld, b, ledger, True, today=today,
                        context={'routing': routing, 'repository': 'o/r'})


def g3(ctx, tmp):
    import reconcile_tickets as rt
    import ticket_governance as tg
    tb = ctx['mods'][3]
    rec = [rt._rec('trivy', 'CVE-2026-0003', 'requirements.txt', 'a3' * 16)]
    routing = {'rules': [{'id': 'cloud', 'match': {'scanner_family': ['iac']}, 'project': 'KIT'}], 'default': None,
               'unresolved': {'owner_role': 'cloud-triage', 'deadline_days': 3}}
    r = tb.install(tb.Replay())
    t = tb.JiraTracker(r)
    tb._sleeps(rt)
    b = tb.backend(rt, tb.JIRA_ENV)
    ledger = {}
    res = _reconcile(rt, b, ledger, routing, '2026-11-06', rec)
    entry = list(ledger.values())[0] if ledger else {}
    ref = entry.get('ref')
    labels = (t.issues.get(str(ref)) or {}).get('fields', {}).get('labels') or []
    check(res['created'] and (entry.get('area') or {}).get('state') == tg.AREA_UNRESOLVED and
          entry['area'].get('owner_role') == 'cloud-triage' and entry['area'].get('due') == '2026-11-09' and
          '%s-area-unresolved' % P in labels and '%s-triage' % P in labels,
          'G3 an unrouted finding was not created in area-unresolved triage with an owner and a deadline: %r %r'
          % (entry.get('area'), labels))
    res = _reconcile(rt, b, ledger, routing, '2026-11-08', rec)
    au = res.get('area_unresolved') or []
    check(au and not au[0]['overdue'] and not [d for d in res['needs_decision']
                                               if d['outcome'] == tg.AREA_UNRESOLVED_OVERDUE],
          'G3 before its deadline the area was owed, or not listed: %r' % au)
    res = _reconcile(rt, b, ledger, routing, '2026-11-12', rec)
    owed = [d for d in res['needs_decision'] if d['outcome'] == tg.AREA_UNRESOLVED_OVERDUE]
    check(owed and 'cloud-triage' in owed[0]['detail'] and rt.exit_code(res) == 1 and
          'no owning area' in rt.render_summary(res),
          'G3 an overdue unresolved area was not a decision owed (exit %s): %r' % (rt.exit_code(res), owed))
    resolved = dict(routing, rules=routing['rules'] + [{'id': 'deps', 'match': {'scanner_family': ['sca']},
                                                        'project': 'KIT'}])
    res = _reconcile(rt, b, ledger, resolved, '2026-11-13', rec)
    entry = ledger[list(ledger)[0]]
    check((entry.get('area') or {}).get('state') == tg.AREA_RESOLVED and entry['area'].get('resolved_by_rule') == 'deps',
          'G3 a rule that now routes it did not resolve the area: %r'
          % entry.get('area'))
    r = tb.install(tb.Replay())
    t = tb.JiraTracker(r)
    b = tb.backend(rt, tb.JIRA_ENV)
    ledger = {}
    _reconcile(rt, b, ledger, None, '2026-11-06', [rt._rec('trivy', 'CVE-2026-0004', 'requirements.txt', 'a4' * 16)])
    check(ledger and not list(ledger.values())[0].get('area'),
          'G3 with no routing configured the kit default was not the area')


def _mc_finding(tt, two_clouds=True):
    f = tt.example_finding(identifier='MFA-BREAKGLASS-1')
    az = dict(f['asset'])
    f['obligations'] = [{'id': 'azure-prod', 'cloud': 'azure', 'owner_role': 'azure-platform', 'asset': az},
                        {'id': 'aws-prod', 'cloud': 'aws' if two_clouds else 'azure',
                         'owner_role': 'aws-platform', 'asset': AWS if two_clouds else az}]
    return f


def g4(ctx, tmp):
    import ticket_governance as tg
    v2, tt = ctx['v2'], ctx['mods'][5]
    v = _v(ctx, os.path.join(tmp, 'a'))
    res = v.submit(v2.fparams(tt, _mc_finding(tt, two_clouds=False)))
    check(v2.codes(res)[1] == tt.TEMPLATE_FIELD_INVALID and not v.t.issues,
          'G4 a multicloud finding naming one cloud was %r' % (v2.codes(res),))
    res = v.submit(v2.fparams(tt, _mc_finding(tt)))
    it = (v2.items(res) or [{}])[0]
    parent, kids = it.get('ref'), it.get('children') or []
    plabels = v.labels(parent) if parent else []
    ok_kids = len(kids) == 2 and all(k.get('ref') for k in kids)
    check(it.get('outcome') == tt.TEMPLATE_TICKET_CREATED and ok_kids and
          '%s-obligations-2' % P in plabels and len(tg.children_of(plabels, P)) == 2 and
          all('%s-owner-%s' % (P, k['owner_role']) in v.labels(k['ref']) and
              '%s-parent-%s' % (P, parent) in v.labels(k['ref']) for k in kids if k.get('ref')),
          'G4 the parent and its two owned child obligations were not created: %r %r' % (it, plabels))
    if not ok_kids:
        return
    az, aws = kids[0]['ref'], kids[1]['ref']
    res = v.submit(v2.closure(tt, parent, 'verify'))
    check(v2.codes(res)[1] == tg.CHILD_OBLIGATION_OPEN and v.status(parent) != 'done',
          'G4 the parent was verified with both children open: %r' % (v2.codes(res),))
    v.raw(v2.closure(tt, az, 'resolve'))
    res = v.submit(v2.closure(tt, az, 'verify'))
    check(v2.outcome(res) == tt.TEMPLATE_TICKET_CLOSED and v.status(az) == 'done' and v.status(parent) != 'done',
          'G4 the first child\'s verification did not close it alone: %r' % (v2.items(res),))
    res = v.submit(v2.closure(tt, aws, 'verify', fixer=ctx['v2'].REVIEWER))
    check(v.status(aws) != 'done' and v.status(parent) != 'done',
          'G4 a fixer verifying their own child obligation closed it')
    res = v.submit(v2.closure(tt, aws, 'verify'))
    check(v.status(aws) == 'done' and v.status(parent) == 'done' and '%s-verified' % P in v.labels(parent) and
          parent in ((res.get('data') or {}).get('parents_closed') or []),
          'G4 the parent did not close when every child was verified: %r' % ((res.get('data') or {}).get('alerts'),))


def mutants(ctx, tmp):
    import ticket_governance as tg
    for name, flag, case in (('M1 a label hit trusted without the key', 'verify_label_hits', g1),
                             ('M2 via trusted without the comparison', 'compare_provenance', g2),
                             ('M3 an overdue area left silent', 'surface_overdue_area', g3),
                             ('M4 a parent closing with a child open', 'hold_parent_for_children', g4)):
        before = len(FAILS)
        setattr(tg, flag, False)
        try:
            case(ctx, tempfile.mkdtemp(dir=tmp))
        except Exception:  # noqa: BLE001 -- a crash under a mutant also kills it
            FAILS.append('crash')
        finally:
            setattr(tg, flag, True)
        killed = len(FAILS) > before
        del FAILS[before:]
        check(killed, '%s survived: its case still passed' % name)


def main():
    try:
        import prove_ticket_intake_v2 as v2
        got = v2.imports()
    except ImportError as exc:
        print('FAIL: cannot import the ticket machinery (%s)' % exc)
        return 2
    if got is None:
        return 2
    pt, mods, _ti, _sod = got
    ctx = {'v2': v2, 'pt': pt, 'mods': mods}
    tmp = tempfile.mkdtemp(prefix='kit-governance-')
    real = __import__('urllib.request').request.urlopen
    try:
        for case in (g1, g2, g3, g4):
            d = tempfile.mkdtemp(dir=tmp)
            try:
                case(ctx, d)
            except (Exception, SystemExit) as exc:  # noqa: BLE001 -- a crash is a failed case, named
                import traceback
                FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                         traceback.format_exc()[-2500:]))
        mutants(ctx, tmp)
    finally:
        __import__('urllib.request').request.urlopen = real
        shutil.rmtree(tmp, ignore_errors=True)
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_ticket_governance: G1..G4 hold and 4 mutants are killed -- the full key is the only identity and a '
          'label is a search aid; via is a claim compared with the authenticated identity and the write event; '
          'area-unresolved has an owner and a deadline and surfaces when overdue; a multicloud parent closes only when '
          'every child obligation is verified')
    return 0


if __name__ == '__main__':
    sys.exit(main())
