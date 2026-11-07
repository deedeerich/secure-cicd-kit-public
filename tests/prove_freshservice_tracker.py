#!/usr/bin/env python3
"""The Freshservice tracker adapter, against a stand-in on 127.0.0.1 (KDEC-043 PROPOSED). NO LIVE TRACKER.

Freshservice's update REPLACES the whole tag list, with no precondition. These cases hold the adapter to its
answer: tags at creation, markers as append-only notes on existing tickets, and -- when tags must change -- read,
merge, write, re-read and verify under a per-ticket lock, reconciling a person's simultaneous edit from the
activity history and never claiming a preservation it cannot prove.

CASES (each the allowed path AND its refusal, docs/PROOF_RULE.md)
    F1  configuration: a complete config builds (positive); http to a host that is not 127.0.0.1, a stamp field
        that is not cf_<name>, a missing requester and two trackers at once are refused by name (negative)
    F2  search-first: the reconciler sweeps by the umbrella tag, finds nothing, creates ONE ticket with every tag
        AT CREATION and the full key in the governed field; the next run binds it and creates nothing (positive);
        a sweep that fails creates nothing and carries the obligation (negative)
    F3  intake: a person's ticket naming the identifier is a candidate; the correlation tag WITH the full key is
        exact; the tag with no full key is only a candidate (KDEC-043 rule 1); a list with no description text
        is PARTIAL, never a quiet subject-only search (negative)
    F4  notes mode (the default): a marker on an existing ticket is a private note and the tags are untouched; a
        person's note that imitates a marker does not count; with the kit's identity unknown, markers refuse
    F5  tags mode, no one else writing: merged, re-read, verified -- a person's existing tag is kept (positive)
    F6  tags mode, A SIMULTANEOUS HUMAN TAG EDIT between the kit's read and write: the kit's whole-list write drops
        the person's tag; the activity history shows it; the kit puts it back and verifies (positive); a person's
        simultaneous REMOVAL stays removed
    F7  tags mode, not provable: the history cannot be read, or a concurrent change is in words the adapter
        cannot read -> TAG_PRESERVATION_NOT_ESTABLISHED, a note asks a person, mark() fails (negative)
    F8  the per-ticket lock: a second writer is refused TICKET_WRITE_LOCK_HELD within its bound; a lock file
        serialises two writers sharing a directory; released, the next writer proceeds
    F9  the description: written when nothing changed since the read (the person's text kept); refused when a
        person saved in between (negative)
    F10 a 429 with Retry-After is waited out within the retry ceiling (positive), and past it is an error
    F11 provenance: the kit's write event is the authenticated identity (established); a ticket a person made
        is a mismatch (negative)
    F12 nothing left 127.0.0.1, and no detail carries the key
    M   named mutants, each must make its case fail: M-F1 no re-read, M-F2 no history reconcile, M-F3 no lock,
        M-F4 a marker by anyone counts

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
CK = 'c' * 32
P = 'secure-cicd-kit'


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def env_for(si, **over):
    import _freshservice_standin as fsi
    e = {'TICKET_BACKEND': 'freshservice', 'FRESHSERVICE_HOST': si.host, 'FRESHSERVICE_API_KEY': fsi.KIT_KEY,
         'FRESHSERVICE_STAMP_FIELD': fsi.STAMP_FIELD, 'FRESHSERVICE_REQUESTER_ID': '77',
         'FRESHSERVICE_CALIBRATION_TICKET': '', 'TICKET_STAMP_LABEL': P, 'TICKET_CREATE_CEILING': '25'}
    e.update(over)
    return dict((k, v) for k, v in e.items() if v is not None)


def world(mods, **over):
    rt, tfs, fsi = mods
    si = fsi.StandIn()
    cal = si.store.manual('calibration', 'a person\'s ticket the kit never wrote')
    b, note = rt.choose_backend(env_for(si, FRESHSERVICE_CALIBRATION_TICKET=cal, **over))
    if b is None:
        si.close()
        raise AssertionError('a complete stand-in config was refused: %s' % note)
    b.validate()
    return si, b


def f1(mods, tmp):
    rt, tfs, fsi = mods
    si = fsi.StandIn()
    try:
        b, note = rt.choose_backend(env_for(si))
        check(b is not None and b.name == 'freshservice' and b.mark_mode == 'notes',
              'F1 a complete config did not build a notes-mode Freshservice backend: %s' % note)
        for label, over, word in (
                ('http to a host that is not 127.0.0.1', {'FRESHSERVICE_HOST': 'http://tracker.example.invalid'}, 'https'),
                ('a stamp field that is not cf_<name>', {'FRESHSERVICE_STAMP_FIELD': 'KitKey'}, 'FRESHSERVICE_STAMP_FIELD'),
                ('no requester id', {'FRESHSERVICE_REQUESTER_ID': None}, 'FRESHSERVICE_REQUESTER_ID'),
                ('an unknown mark mode', {'FRESHSERVICE_MARK_MODE': 'labels'}, 'FRESHSERVICE_MARK_MODE'),
                ('two trackers at once', {'JIRA_HOST': 'https://example.atlassian.net', 'JIRA_EMAIL': 'x@example.invalid',
                                          'JIRA_TOKEN': 'placeholder', 'JIRA_PROJECT': 'KIT'}, 'CONFIGURATION DEFECT')):
            b, note = rt.choose_backend(env_for(si, **over))
            check(b is None and word in note, 'F1 %s was not refused by name: %r' % (label, note))
    finally:
        si.close()


def f2(mods, tmp):
    rt, tfs, fsi = mods
    si, b = world(mods)
    try:
        recs = [rt._rec('trivy', 'CVE-2026-0001', 'requirements.txt', 'f2' * 16)]
        cl, wh = rt.build_clusters(recs)
        cl[0]['template_labels'] = ['%s-tpl-finding' % P, '%s-sev-high' % P]
        ledger = {}
        r1 = rt.reconcile(cl, wh, b, ledger, True, today='2026-11-06')
        made = [t for t in si.store.tickets.values() if P in t['tags']]
        posts = [r for r in si.store.requests if r['method'] == 'POST' and r['path'] == '/api/v2/tickets']
        check(len(made) == 1 and made[0]['custom_fields'].get(fsi.STAMP_FIELD) == cl[0]['cluster_key'] and
              '%s-tpl-finding' % P in made[0]['tags'] and posts and 'tags' in posts[-1]['json'],
              'F2 the first run did not create ONE ticket, tags at creation, full key in the field: %r' % (r1['created'],))
        sweeps = [r for r in si.store.requests if r['path'] == '/api/v2/tickets/filter']
        check(sweeps and sweeps[0]['query'].find('tag') >= 0 and
              si.store.requests.index(sweeps[0]) < si.store.requests.index(posts[-1]),
              'F2 the lookup did not precede the create')
        cl2, wh2 = rt.build_clusters(recs)
        n = len(si.store.tickets)
        r2 = rt.reconcile(cl2, wh2, b, ledger, True, today='2026-11-07')
        check(len(si.store.tickets) == n and not r2['created'] and
              (r2['outcomes'].get('LEDGER_BOUND') or r2['outcomes'].get('BACKEND_BOUND')),
              'F2 the second run did not bind the ticket: %r' % (r2['outcomes'],))
        si.store.fail[('GET', r'/tickets/filter')] = 500
        cl3, wh3 = rt.build_clusters([rt._rec('trivy', 'CVE-2026-0002', 'requirements.txt', 'f3' * 16)])
        r3 = rt.reconcile(cl3, wh3, b, {}, True, today='2026-11-07')
        check(len(si.store.tickets) == n and r3['obligations'] and
              r3['ticketing_claim']['routing_result'] == 'EVIDENCE_UNTRUSTED',
              'F2 a failed sweep created a ticket or lost the obligation: %r' % (r3['obligations'],))
    finally:
        si.close()


def f3(mods, tmp):
    rt, tfs, fsi = mods
    import ticket_intake as ti
    si, b = world(mods)
    try:
        manual = si.store.manual('TLS 1.0 on acct1', 'the audit found RULE-X on acct1')
        verified = si.store.manual('linked by a review', 'notes\nsecure-cicd-kit-correlation-key: %s' % CK,
                                   tags=['%s-ck-%s' % (P, CK)])
        bare = si.store.manual('a label only', 'no key here', tags=['%s-ck-%s' % (P, CK)])
        a = ti.adapter_for(b)
        check(a.name == 'freshservice', 'F3 the adapter for a Freshservice backend is %r' % a.name)
        got, state, _d = a.search_all(text='RULE-X', ck_label='%s-ck-%s' % (P, CK))
        m = ti.match({'correlation_key': CK, 'rule': 'RULE-X', 'aliases': [], 'asset_needle': 'acct1', 'title': ''},
                     got, '%s-ck-%s' % (P, CK), 'secure-cicd-kit-cluster:', 85)
        ex = [t['ref'] for t, _b in m['exact']]
        cands = dict((t['ref'], basis) for t, basis, _s in m['candidates'])
        check(state == ti.TRACKER_INTAKE_COMPLETE and ex == [verified] and cands.get(manual) == 'asset+identifier' and
              cands.get(bare) == 'correlation-label-unverified',
              'F3 exact/candidate/unverified were %r %r (%s)' % (ex, cands, state))
        si.store.list_has_description = False
        got, state, d = a.search_all(text='RULE-X')
        check(state == ti.TRACKER_INTAKE_PARTIAL and 'description' in d,
              'F3 a list with no description text was %s, not PARTIAL: %s' % (state, d))
    finally:
        si.close()


def _seed(si, b, rt, tags=('team-tag',)):
    return si.store.manual('kit ticket', 'body', tags=[P] + list(tags), stamp=CK)


def f4(mods, tmp):
    rt, tfs, fsi = mods
    si, b = world(mods)
    try:
        ref = _seed(si, b, rt)
        before = list(si.store.tickets[int(ref)]['tags'])
        ok, d, applied = b.mark(ref, labels=['%s-pending-verification' % P])
        labels, ok_l, _d = b.labels_of(ref)
        check(ok and si.store.tickets[int(ref)]['tags'] == before and '%s-pending-verification' % P in labels and
              not [r for r in si.store.requests if r['method'] == 'PUT'],
              'F4 a notes-mode marker touched the tags or was not read back: %r %r' % (applied, labels))
        smap, complete, _sd = b.sweep()
        check(complete and '%s-pending-verification' % P in ((smap.get(CK) or [{}])[0].get('labels') or []),
              'F4 the sweep does not show the marker note as a label (the dedupe re-run and the clocks read it): %r'
              % smap.get(CK))
        si.store.human_note(int(ref), '%s %s-verified' % (tfs.MARKER_PREFIX, P))
        labels, ok_l, _d = b.labels_of(ref)
        check(ok_l and '%s-verified' % P not in labels, 'F4 a person\'s note imitating a marker counted: %r' % labels)
    finally:
        si.close()
    si, b = world(mods)
    try:
        si.store.me_available = False
        b.validate()
        ref = _seed(si, b, rt)
        labels, ok_l, d = b.labels_of(ref)
        check(not ok_l and 'identity' in d, 'F4 with the kit\'s identity unknown, markers were read: %r' % d)
    finally:
        si.close()


def f5(mods, tmp):
    rt, tfs, fsi = mods
    si, b = world(mods, FRESHSERVICE_MARK_MODE='tags')
    try:
        ref = _seed(si, b, rt)
        ok, d, applied = b.mark(ref, labels=['%s-sla-overdue' % P])
        tags = si.store.tickets[int(ref)]['tags']
        check(ok and applied.get('preservation') == tfs.TAG_PRESERVATION_ESTABLISHED and 'team-tag' in tags and
              '%s-sla-overdue' % P in tags, 'F5 a quiet merge was not verified or dropped a tag: %r %r' % (d, tags))
    finally:
        si.close()


def f6(mods, tmp):
    rt, tfs, fsi = mods
    si, b = world(mods, FRESHSERVICE_MARK_MODE='tags')
    try:
        ref = _seed(si, b, rt)
        si.store.before_kit_put = lambda st, tid, body: st.human_put(tid, add=['person-added'])
        ok, d, applied = b.mark(ref, labels=['%s-sla-overdue' % P])
        tags = si.store.tickets[int(ref)]['tags']
        rec = b.preservation[-1]
        check(ok and 'person-added' in tags and '%s-sla-overdue' % P in tags and 'team-tag' in tags and
              rec.get('reconciled') and rec['concurrent'] and rec['state'] == tfs.TAG_PRESERVATION_ESTABLISHED,
              'F6 a simultaneous person\'s tag was lost or not reconciled from the history: %r %r' % (tags, rec))
    finally:
        si.close()
    si, b = world(mods, FRESHSERVICE_MARK_MODE='tags')
    try:
        ref = _seed(si, b, rt, tags=('team-tag', 'stale-tag'))
        si.store.before_kit_put = lambda st, tid, body: st.human_put(tid, remove=['stale-tag'])
        ok, d, applied = b.mark(ref, labels=['%s-sla-overdue' % P])
        tags = si.store.tickets[int(ref)]['tags']
        check(ok and 'stale-tag' not in tags and '%s-sla-overdue' % P in tags,
              'F6 a person\'s simultaneous removal was undone by the kit: %r' % tags)
    finally:
        si.close()


def f7(mods, tmp):
    rt, tfs, fsi = mods
    for label, setup in (('the history cannot be read', lambda st: st.fail.__setitem__(('GET', r'/activities'), 500)),
                         ('a concurrent change in unreadable words', lambda st: setattr(st, 'tag_words', 'opaque'))):
        si, b = world(mods, FRESHSERVICE_MARK_MODE='tags')
        try:
            ref = _seed(si, b, rt)
            setup(si.store)
            si.store.before_kit_put = lambda st, tid, body: st.human_put(tid, add=['person-added'])
            ok, d, applied = b.mark(ref, labels=['%s-sla-overdue' % P])
            notes = [n['body'] for n in si.store.notes.get(int(ref), [])]
            check(not ok and applied.get('preservation') == tfs.TAG_PRESERVATION_NOT_ESTABLISHED and
                  any(tfs.TAG_PRESERVATION_NOT_ESTABLISHED in n for n in notes),
                  'F7 %s was claimed preserved, or no person was asked: %r %r' % (label, d, applied))
        finally:
            si.close()


def f8(mods, tmp):
    rt, tfs, fsi = mods
    locks = tfs.TicketLocks()
    ok1, _d = locks.acquire('7')
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.setdefault('r', locks.acquire('7', wait=0.2)))
    t.start()
    t.join(5)
    check(ok1 and out.get('r') and not out['r'][0] and tfs.TICKET_WRITE_LOCK_HELD in out['r'][1],
          'F8 a second writer to the same ticket was not refused within its bound: %r' % (out,))
    locks.release('7')
    check(locks.acquire('7', wait=0.2)[0], 'F8 a released lock was not available')
    locks.release('7')
    d = os.path.join(tmp, 'locks')
    os.makedirs(d)
    a, c = tfs.TicketLocks(d), tfs.TicketLocks(d)
    ok_a, _x = a.acquire('9')
    ok_c, why = c.acquire('9', wait=0.3)
    check(ok_a and not ok_c and tfs.TICKET_WRITE_LOCK_HELD in why,
          'F8 a lock file did not serialise two writers sharing a directory: %r' % why)
    a.release('9')
    check(c.acquire('9', wait=0.3)[0], 'F8 the lock file was not released')
    c.release('9')


def f9(mods, tmp):
    rt, tfs, fsi = mods
    si, b = world(mods)
    try:
        ref = si.store.manual('kit ticket', 'a person wrote this', tags=[P], stamp=CK)
        desc, ok, _d = b.read_description(ref)
        new, _f = b.splice_description(desc, '%s\nblock\n%s' % (rt.BLOCK_OPEN, rt.BLOCK_CLOSE))
        okw, dw = b.write_description(ref, new, desc)
        text = si.store.tickets[int(ref)]['description']
        check(okw and 'a person wrote this' in text and 'block' in text, 'F9 an unchanged ticket was not written: %s' % dw)
        desc, ok, _d = b.read_description(ref)
        si.store.human_put(int(ref), add=['x'])
        new, _f = b.splice_description(desc, '%s\nblock 2\n%s' % (rt.BLOCK_OPEN, rt.BLOCK_CLOSE))
        okw, dw = b.write_description(ref, new, desc)
        check(not okw and 'changed since it was read' in dw and 'block 2' not in si.store.tickets[int(ref)]['description'],
              'F9 a description a person saved in between was written over: %s' % dw)
    finally:
        si.close()


def f10(mods, tmp):
    rt, tfs, fsi = mods
    import prove_ticket_backends as tb
    waited = tb._sleeps(rt)
    si, b = world(mods)
    try:
        b.retry_ceiling = 1
        si.store.throttle = 1
        t, ok, _d = b.resolve(si.store.manual('x', 'y'))
        check(ok and waited and waited[-1] == 1, 'F10 a 429 with Retry-After 1 was not waited out: %r %r' % (ok, waited))
        b.retry_ceiling = 0
        si.store.throttle = 1
        t, ok, d = b.resolve(si.store.manual('x', 'y'))
        check(not ok, 'F10 a 429 past the retry ceiling was read as an answer')
    finally:
        si.close()


def f11(mods, tmp):
    rt, tfs, fsi = mods
    import ticket_governance as tg
    si, b = world(mods)
    try:
        recs = [rt._rec('trivy', 'CVE-2026-0011', 'requirements.txt', 'fb' * 16)]
        cl, wh = rt.build_clusters(recs)
        rt.reconcile(cl, wh, b, {}, True, today='2026-11-06')
        ref = [str(i) for i, t in si.store.tickets.items() if P in t['tags']][0]
        actor, _d = b.write_event(ref)
        rec = tg.provenance('kit-api', b.authenticated_identity(), actor, {'kit-api': str(fsi.KIT_AGENT)})
        check(rec['state'] == tg.PROVENANCE_ESTABLISHED, 'F11 the kit\'s own write was %r' % rec)
        person = si.store.manual('a person made this', 'x', tags=[P, '%s-via-kit-api' % P])
        actor, _d = b.write_event(person)
        rec = tg.provenance('kit-api', b.authenticated_identity(), actor, {'kit-api': str(fsi.KIT_AGENT)})
        check(rec['state'] == tg.PROVENANCE_MISMATCH, 'F11 a person\'s ticket claiming the kit was %r' % rec)
    finally:
        si.close()


def f12(mods, tmp, seen):
    import _freshservice_standin as fsi
    check(seen and all(str(h or '').startswith('127.0.0.1:') for h in seen),
          'F12 a request left 127.0.0.1: %r' % sorted(set(seen))[:5])
    check(not any(fsi.KIT_KEY in str(f) for f in FAILS), 'F12 a failure text carries the API key')


def mutants(mods, tmp):
    rt, tfs, fsi = mods
    import ticket_governance as tg
    for name, mod, flag, case in (('M-F1 no re-read after the tag write', tfs, 'verify_after_write', f6),
                                  ('M-F2 no history reconcile', tfs, 'reconcile_from_history', f6),
                                  ('M-F3 no per-ticket lock', tfs, 'lock_per_ticket', f8),
                                  ('M-F4 a marker by anyone counts', tfs, 'markers_need_kit_author', f4)):
        before = len(FAILS)
        setattr(mod, flag, False)
        try:
            d = tempfile.mkdtemp(dir=tmp)
            case(mods, d)
        except Exception:  # noqa: BLE001 -- a crash under a mutant also kills it
            FAILS.append('crash')
        finally:
            setattr(mod, flag, True)
        killed = len(FAILS) > before
        del FAILS[before:]
        check(killed, '%s survived: its case still passed' % name)
    del tg


def main():
    try:
        import reconcile_tickets as rt
        import tracker_freshservice as tfs
        import _freshservice_standin as fsi
    except ImportError as exc:
        print('FAIL: cannot import the Freshservice machinery (%s)' % exc)
        return 2
    mods = (rt, tfs, fsi)
    tmp = tempfile.mkdtemp(prefix='kit-freshservice-')
    seen = []
    orig = fsi.Store.__init__

    def tracking_init(self):
        orig(self)
        self.requests = _Seen(seen)
    fsi.Store.__init__ = tracking_init
    try:
        for case in (f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11):
            d = tempfile.mkdtemp(dir=tmp)
            try:
                case(mods, d)
            except (Exception, SystemExit) as exc:  # noqa: BLE001 -- a crash is a failed case, named
                import traceback
                FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                         traceback.format_exc()[-2000:]))
        f12(mods, tmp, seen)
        mutants(mods, tmp)
    finally:
        fsi.Store.__init__ = orig
        shutil.rmtree(tmp, ignore_errors=True)
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_freshservice_tracker: F1..F12 hold and 4 mutants are killed -- search-first, tags at creation, '
          'markers as append-only notes, read-merge-write-verify under a per-ticket lock, a simultaneous human tag edit '
          'reconciled from the activity history, NOT_ESTABLISHED when it cannot be proven; stand-in on 127.0.0.1 only')
    return 0


class _Seen(list):
    """The stand-in's request log, also recording every Host header the adapter sent."""

    def __init__(self, sink):
        list.__init__(self)
        self.sink = sink

    def append(self, r):
        self.sink.append(r.get('host'))
        list.append(self, r)


if __name__ == '__main__':
    sys.exit(main())
