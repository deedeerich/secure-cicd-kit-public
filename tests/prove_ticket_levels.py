#!/usr/bin/env python3
"""TICKET OVERFLOW, CONTINUITY, TAGS, THE TWO COMPLETION LEVELS, THE QUALIFYING RESCAN AND RECURRENCE (KDEC-062).

Owner rulings 2026-11-16 (decisions.md KDEC-062). Fixture proofs only: no live tracker is touched.

    O1  instance overflow: 30 instances over a threshold of 25 -- 25 children, every instance and its evidence kept
        in the ledger, the 5 not itemised NAMED, the overflow ESCALATED (needs_decision, exit 1) and in the summary
    O2  under the threshold: no overflow, nothing escalated
    C1  register NOT established: an exact duplicate is NOT closed automatically (TEMPLATE_DUPLICATE_CLOSURE_REFUSED,
        the record stays open, the evidence kept); with REGISTER_READ the same duplicate closes
    C2  register NOT established: no remediation clearance -- a rescan closure is refused naming the state
    C3  register NOT established: no risk-acceptance carry-forward -- an enhancement names the state, an approved
        disposition is flagged for re-evaluation and nothing is extended or closed
    T1  the tag taxonomy: four classes from config; a configured label in the protected namespace is refused
    T2  a person's label survives every reconcile path on Jira, Azure DevOps and GitHub (create, member update,
        clearance close, recurrence reopen) and is carried to a successor ticket
    T3  a hand-added protected level label changes no state (SYSTEM_LABEL_UNATTESTED, the ledger decides)
    L1  level 1 by the fixer: recorded as their disposition (not independent), projected to the mapped status
    L2  level 2: the level-1 actor is REFUSED (named, the record stays level 1, the ticket not finalised); a distinct
        authorised person finalises; the tracker word is configuration (mapped / unmapped named)
    L3  level 2 by rescan: allowed only when qualifying
    R1  the qualifying rescan: each disqualifier is named (still present, scanner not run / not completed, output
        missing, path removed, path excluded, out of scope, scope changed, config changed, basis not recorded,
        path state not established); all good is RESCAN_QUALIFYING
    R2  the reconciler's clearance: a removed file or an excluded path closes nothing (named); a full rescan with a
        path inventory closes and finalises (level 2); without the inventory it closes and is NOT finalised
    P1  scan_report writes the path inventory a rescan needs: the tracked files of the scanned checkout; no
        checkout, or not a git checkout, is PATH_INVENTORY_NOT_ESTABLISHED (never an empty list)
    X1  recurrence after level 2: a NEW linked ticket naming its predecessor, history kept, deterministic (a second
        run adds nothing); before level 2 the existing reopen policy is unchanged
    Mutants MX1-MX6, each caught at its own claim.

USAGE: python3 tests/prove_ticket_levels.py   (no network; exit 0 PASS, 1 FAIL)
"""
import contextlib
import inspect
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, os.path.join(ROOT, 'tests'))

import reconcile_tickets as RT      # noqa: E402
import ticket_completion as TC      # noqa: E402
import ticket_submit as TSUB        # noqa: E402
import ticket_templates as TT       # noqa: E402

STAMP = 'secure-cicd-kit'
APPR = RT.tm.Approval(actor='platform-security', reason='prove_ticket_levels')
SHA = 'c' * 64


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def _ptl():
    import prove_ticket_lifecycle as PTL
    return PTL


# ── O: overflow ───────────────────────────────────────────────────────────────────────────

def overflow_run(n, limit):
    be = RT.RecordingBackend()
    be.instance_threshold = limit
    recs = [RT._rec('trivy', 'CVE-OV', 'go.mod', 'id-ov-%02d' % i, aliases=['cve-ov'], line=i + 1) for i in range(n)]
    led = {}
    r = _quiet(RT.reconcile, *_quiet(RT.build_clusters, recs), backend=be, ledger=led, apply_changes=True,
               approval=APPR, today='2026-11-16')
    return r, led, be


def claims_o(c):
    r, led, be = overflow_run(30, 25)
    e = next(iter(led.values()), {}) if led else {}
    ov = [o for o in r.get('ceiling_overflow') or [] if o['setting'] == 'ticket_instance_threshold']
    nd = [d for d in r.get('needs_decision') or [] if d.get('outcome') == RT.TICKET_CEILING_OVERFLOW]
    allids = ['id-ov-%02d' % i for i in range(30)]
    c('O1 30 instances over 25: 25 children, every instance and its evidence kept in the ledger, nothing truncated',
      len(be.instances) == 25 and sorted(e.get('member_identities') or []) == allids and
      sorted((e.get('members') or {}).keys()) == allids and len(e.get('instances') or {}) == 25 and
      e.get('instances_not_itemised') == 5, (len(be.instances), e.get('instances_not_itemised')))
    c('O1 the 5 not itemised are NAMED in the ledger and the run receipt (not just counted)',
      sorted(e.get('instances_overflow') or []) == allids[25:] and len(ov) == 1 and
      sorted(ov[0].get('identities') or []) == allids[25:] and ov[0].get('total') == 30 and
      ov[0].get('itemised') == 25 and ov[0].get('over_by') == 5, (e.get('instances_overflow'), ov))
    c('O1 the instance overflow is ESCALATED for a reviewer (needs_decision, exit 1) and in the summary',
      len(nd) == 1 and RT.exit_code(r) == 1 and 'ticket_instance_threshold' in RT.render_summary(r), nd)
    r2, _l2, be2 = overflow_run(3, 25)
    c('O2 3 instances under 25: all itemised, no overflow, nothing escalated',
      len(be2.instances) == 3 and not r2.get('ceiling_overflow') and
      not [d for d in r2.get('needs_decision') or [] if d.get('outcome') == RT.TICKET_CEILING_OVERFLOW], '')


# ── C: continuity ─────────────────────────────────────────────────────────────────────────

def _grp(register, dispositions=None, enhances=False):
    g = {'item': 0, 'correlation_key': 'k' * 32, 'identity': 'id-c', 'template': 'finding', 'tool': 'aikido',
         'source_type': 'tool', 'uri': 'app/x.py', 'severity': 'high', 'title': 't', 'rule': 'CVE-1',
         'provenance': {'evidence_ref': 'ev://1', 'evidence_sha256': SHA}, 'template_labels': [],
         'baseline': {'state': 'BASELINE_SELECTED', 'register': register}}
    if enhances:
        g['enhances'] = {'correlation_key': 'e' * 32, 'severity': 'high', 'dispositions': dispositions or []}
    return [g]


def _sub_ctx(be, ledger, **kw):
    ctx = {'rt': RT, 'backend': be, 'ledger': ledger, 'today': '2026-11-16', 'settings': {}, 'default_branch': 'main',
           'branch_map': '', 'approver_source': 'list:sec-two'}
    ctx.update(kw)
    return ctx


def _new_ticket(be, ck, labels=()):
    ref, _d = be.create({'cluster_key': ck}, 'body', 'title')
    for r in be.store[ck]:
        if r['ref'] == ref:
            r['labels'] = list(labels)
    return ref


def dup_run(register):
    be = RT.RecordingBackend()
    be.close_attempts = []
    orig = be.close

    def close(ref_):
        be.close_attempts.append(str(ref_))
        return orig(ref_)
    be.close = close
    ck = 'k' * 32
    ref = _new_ticket(be, ck, ['%s-ck-%s' % (STAMP, ck)])
    target = {'ref': ref, 'key': ref, 'labels': ['%s-tool-semgrep' % STAMP], 'state': 'open'}
    plan = TSUB.Plan()
    grp = _grp(register)
    ctx = _sub_ctx(be, {})
    TSUB._plan_exact(ctx, plan, grp, target, 'stamp', STAMP, (50, 'b'), (50, 'b'))
    data = {'notifications': []}
    _quiet(TSUB._write, ctx, {'review_id': 'rev-1'}, plan, STAMP, '%s-ck-' % STAMP, 'sec-two', APPR, False, data)
    return be, plan, ref


def claims_c(c):
    be, plan, ref = dup_run('REGISTER_NOT_ESTABLISHED')
    dref = [i['ref'] for i in be.instances]
    out = [i.get('outcome') for i in plan.items]
    c('C1 register NOT established: the exact duplicate is recorded, evidence kept, and NOT closed automatically',
      dref and not (set(dref) & set(be.close_attempts)) and out == [TT.TEMPLATE_DUPLICATE_CLOSURE_REFUSED] and
      any('REGISTER_NOT_ESTABLISHED' in t for _r, t in be.comments) and
      any('kit-observation sha256:' in t for r, t in be.comments if r == ref), (out, be.closed, dref))
    be2, plan2, _ref2 = dup_run('REGISTER_READ')
    c('C1 positive control: with REGISTER_READ the same duplicate closes (the hold is the register state, nothing else)',
      [i['ref'] for i in be2.instances] and set(i['ref'] for i in be2.instances) <= set(be2.close_attempts) and
      [i.get('outcome') for i in plan2.items] == [TT.TEMPLATE_CLOSED_DUPLICATE], (be2.close_attempts, plan2.items))

    # C2: a rescan closure with the register not established.
    be3 = RT.RecordingBackend()
    ck = 'r' * 32
    ref3 = _new_ticket(be3, ck)
    it = {'ref': ref3, 'action': 'verify', 'requested_by': 'app', 'fixed_by': 'dev-one',
          'evidence': {'ref': 'ev://f', 'sha256': SHA}, 'verification': {'kind': 'scan', 'run_id': 7}}
    plan3 = TSUB.Plan()
    ctx3 = _sub_ctx(be3, {}, register_state='REGISTER_NOT_ESTABLISHED',
                    evidence=lambda rid, any_branch=False: ({'id': rid, 'head_branch': 'main'}, [], {'rows': []}, None))
    r = TSUB._plan_closure(ctx3, plan3, 0, it, [], ck, 'sec-two', {'notifications': []})
    c('C2 register NOT established: a rescan clearance is refused, naming the register state; nothing is closed',
      r is not None and 'REGISTER_NOT_ESTABLISHED' in json.dumps(r) and not plan3.actions and not be3.closed, r)

    # C3: an enhancement carrying an approved disposition, register not established.
    be4 = RT.RecordingBackend()
    eck = 'e' * 32
    ref4 = _new_ticket(be4, eck)
    plan4 = TSUB.Plan()
    grp4 = _grp('REGISTER_NOT_ESTABLISHED', dispositions=[{'type': 'ACCEPTED_RISK', 'expires': '2027-01-01'}],
                enhances=True)
    TSUB._plan_enhance(plan4, grp4, {'ref': ref4, 'key': ref4, 'labels': [], 'state': 'open'}, 'stamp', STAMP,
                       (50, 'b'), (50, 'b'))
    _quiet(TSUB._write, _sub_ctx(be4, {}), {'review_id': 'rev-1'}, plan4, STAMP, '%s-ck-' % STAMP, 'sec-two', APPR,
           False, {'notifications': []})
    row = plan4.items[0] if plan4.items else {}
    said = ' '.join(t for r_, t in be4.comments if r_ == ref4)
    c('C3 register NOT established: no risk-acceptance carry-forward -- the state named on the row and the ticket, '
      'the disposition flagged for re-evaluation, nothing extended or closed',
      row.get('continuity') == 'REGISTER_NOT_ESTABLISHED' and row.get('disposition_review') and
      'REGISTER_NOT_ESTABLISHED' in said and 'not carried forward' in said and not be4.closed and
      not [a for a in plan4.actions if a[0] in ('extend', 'close')], (row, said[-300:]))


# ── T: tags ───────────────────────────────────────────────────────────────────────────────

TAXONOMY = {'source_labels': {'aikido': 'src-aikido-org'}, 'metadata': {'application': 'app-under-test'},
            'completion_statuses': {'recording': {'level1': 'Resolved-by-team', 'level2': 'Verified-final'}}}


def claims_t(c):
    labs = ['%s-triage' % STAMP, 'src-aikido-org', '%s-meta-application-app-under-test' % STAMP, 'team-alpha']
    k = TC.classify_labels(labs, STAMP, TAXONOMY)
    c('T1 four classes from config: system, source, metadata, user',
      k == {'system': ['%s-triage' % STAMP], 'source': ['src-aikido-org'],
            'metadata': ['%s-meta-application-app-under-test' % STAMP], 'user': ['team-alpha']}, k)
    c('T1 the configured labels are produced from config only (no invented names)',
      TC.kit_labels(TAXONOMY, STAMP, ['aikido']) == sorted(['src-aikido-org',
                                                           '%s-meta-application-app-under-test' % STAMP])
      and TC.kit_labels({}, STAMP, ['aikido']) == [], TC.kit_labels(TAXONOMY, STAMP, ['aikido']))
    bad = TC.taxonomy_problems({'source_labels': {'x': '%s-verified' % STAMP, 'y': 'two words'}}, STAMP)
    c('T1 a configured source label in the protected namespace, or not one token, is refused by name',
      [s for s, _d in bad] == [TC.TAXONOMY_LABEL_PROTECTED, TC.TAXONOMY_LABEL_INVALID], bad)

    PTL = _ptl()
    for T in PTL.TRACKERS:
        tr = T(RT)
        led = {}
        rec = PTL.obs('trivy', 'CVE-T2', 'go.mod', 'id-t2', ['cve-t2'])
        _quiet(PTL.run, RT, tr, [rec], led, '2026-10-01', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        ref = PTL.only_ref(led)
        if not ref:
            c('T2 %s the first run created a ticket' % tr.name, False, led)
            continue
        _add_human_label(tr, ref)
        steps = []
        rec2 = PTL.obs('grype', 'CVE-T2', 'go.mod', 'id-t2b', ['cve-t2'])
        _quiet(PTL.run, RT, tr, [rec, rec2], led, '2026-10-02',
               PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True, grype=True)))
        steps.append(('member update', 'team-alpha' in tr.labels(ref)))
        _quiet(PTL.run, RT, tr, [], led, '2026-10-03', PTL.ctx(PTL.RUN2, coverage=PTL.cov(trivy=True, grype=True)))
        steps.append(('clearance close', tr.closed(ref) and 'team-alpha' in tr.labels(ref)))
        _quiet(PTL.run, RT, tr, [rec], led, '2026-10-04', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        steps.append(('recurrence reopen', (not tr.closed(ref)) and 'team-alpha' in tr.labels(ref)))
        c('T2 %s a person\'s label survives create, member update, clearance close and recurrence reopen' % tr.name,
          all(ok for _s, ok in steps), steps)
    # The successor path (a refused reopen): the person's label is carried to the successor.
    tr = PTL.Jira(RT)
    led = {}
    rec = PTL.obs('trivy', 'CVE-T2S', 'go.mod', 'id-t2s', ['cve-t2s'])
    _quiet(PTL.run, RT, tr, [rec], led, '2026-10-01', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
    ref = PTL.only_ref(led)
    _add_human_label(tr, ref)
    _quiet(PTL.run, RT, tr, [], led, '2026-10-02', PTL.ctx(PTL.RUN2, coverage=PTL.cov(trivy=True)))
    _quiet(PTL.run, RT, tr, [rec], led, '2026-10-03', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)),
           JIRA_TRANSITION_REOPEN='')
    new = PTL.only_ref(led)
    c('T2 jira a refused reopen: the successor carries the person\'s label; the predecessor keeps it',
      new and new != ref and 'team-alpha' in tr.labels(new) and 'team-alpha' in tr.labels(ref),
      (ref, new, tr.labels(new) if new else None))

    # T3: a hand-added level-2 label.
    entry = {'ref': '1', 'completion': {'level': TC.COMPLETION_L1_DONE, 'level1': {'actor': 'dev-one'}}}
    labs3 = [TC.level_label(TC.COMPLETION_L2_FINAL, STAMP), TC.level_label(TC.COMPLETION_L1_DONE, STAMP)]
    un = TC.unattested_level_labels(entry, labs3, STAMP)
    c('T3 a hand-added protected level-2 label: SYSTEM_LABEL_UNATTESTED, the recorded level stands, no recurrence '
      'ticket is planned from it',
      [u['label'] for u in un] == [TC.level_label(TC.COMPLETION_L2_FINAL, STAMP)] and
      TC.level_of(entry) == TC.COMPLETION_L1_DONE and TC.plan_recurrence(entry) is None, un)


def _add_human_label(tr, ref):
    if tr.name == 'jira':
        tr.t.issues[str(ref)]['fields'].setdefault('labels', []).append('team-alpha')
    elif tr.name == 'azdo':
        f = tr.t.items[int(ref)]['fields']
        f['System.Tags'] = '; '.join([x for x in [f.get('System.Tags') or ''] if x] + ['team-alpha'])
    else:
        tr.t.issues[int(ref)]['labels'].append({'name': 'team-alpha'})


# ── L: the two levels (tickets.submit closure template) ───────────────────────────────────

def closure(be, ledger, ck, ref, action, fixed_by, approver, kind='reviewer', run_id=None, evidence=None,
            taxonomy=None, register_state=None):
    it = {'ref': ref, 'action': action, 'requested_by': 'app', 'fixed_by': fixed_by,
          'evidence': {'ref': 'ev://fix', 'sha256': SHA}, 'verification': {'kind': kind}}
    if run_id is not None:
        it['verification']['run_id'] = run_id
    kw = {'taxonomy': taxonomy or {}}
    if evidence:
        kw['evidence'] = evidence
    if register_state:
        kw['register_state'] = register_state
    ctx = _sub_ctx(be, ledger, **kw)
    plan = TSUB.Plan()
    data = {'notifications': []}
    r = TSUB._plan_closure(ctx, plan, 0, it, [], ck, approver, data)
    if r is None:
        _quiet(TSUB._write, ctx, {'review_id': 'rev-1'}, plan, STAMP, '%s-ck-' % STAMP, approver, APPR, False, data)
    return r, plan


def _status(be, ref):
    for recs in be.store.values():
        for x in recs:
            if x['ref'] == str(ref):
                return x.get('state'), x.get('status_name')
    return None, None


def claims_l(c):
    be = RT.RecordingBackend()
    ck = 'l' * 32
    ref = _new_ticket(be, ck)
    led = {ck: {'ref': ref, 'member_identities': ['id-l']}}
    r, plan = closure(be, led, ck, ref, 'resolve', 'dev-one', 'dev-one', taxonomy=TAXONOMY)
    comp = (led[ck].get('completion') or {})
    c('L1 the fixer sets level 1: recorded as THEIR disposition (not independent), projected to the mapped status',
      r is None and comp.get('level') == TC.COMPLETION_L1_DONE and (comp.get('level1') or {}).get('actor') == 'dev-one'
      and (comp.get('level1') or {}).get('independent') is False and _status(be, ref)[1] == 'Resolved-by-team', comp)
    r, plan = closure(be, led, ck, ref, 'verify', 'dev-one', 'dev-one', taxonomy=TAXONOMY)
    row = plan.items[0] if plan.items else {}
    c('L2 the level-1 actor asking for level 2 is REFUSED by name; the record stays level 1, nothing finalised',
      row.get('completion_refusal') == TC.COMPLETION_L2_SAME_ACTOR and
      TC.level_of(led[ck]) == TC.COMPLETION_L1_DONE and _status(be, ref)[1] != 'Verified-final', (row, led[ck]))
    # A different fixer named on the item does not launder the recorded level-1 actor.
    r, plan = closure(be, led, ck, ref, 'verify', 'someone-else', 'dev-one', taxonomy=TAXONOMY)
    row = plan.items[0] if plan.items else {}
    c('L2 the recorded level-1 actor is refused even when the item names another fixer',
      row.get('completion_refusal') == TC.COMPLETION_L2_SAME_ACTOR and TC.level_of(led[ck]) == TC.COMPLETION_L1_DONE,
      row)
    r, plan = closure(be, led, ck, ref, 'verify', 'dev-one', 'sec-two', taxonomy=TAXONOMY)
    c('L2 a distinct authorised person sets level 2; the tracker gets the CONFIGURED level-2 status',
      r is None and TC.level_of(led[ck]) == TC.COMPLETION_L2_FINAL and
      ((led[ck].get('completion') or {}).get('level2') or {}).get('actor') == 'sec-two' and
      _status(be, ref)[1] == 'Verified-final', (r, led[ck].get('completion'), _status(be, ref)))
    c('L2 the tracker word is configuration: mapped -> the name, unmapped -> COMPLETION_STATUS_UNMAPPED',
      TC.tracker_status(TC.COMPLETION_L2_FINAL, 'recording', TAXONOMY) == ('Verified-final', TC.COMPLETION_STATUS_MAPPED)
      and TC.tracker_status(TC.COMPLETION_L2_FINAL, 'jira', TAXONOMY) == (None, TC.COMPLETION_STATUS_UNMAPPED), '')
    # Unmapped: level 2 falls back to the tracker's done state and the row says so.
    be2 = RT.RecordingBackend()
    ref2 = _new_ticket(be2, ck)
    led2 = {ck: {'ref': ref2, 'member_identities': ['id-l'],
                 'completion': {'level': TC.COMPLETION_L1_DONE, 'level1': {'actor': 'dev-one'}}}}
    r, plan = closure(be2, led2, ck, ref2, 'verify', 'dev-one', 'sec-two')
    c('L2 unmapped: the tracker\'s done state is used and the row names COMPLETION_STATUS_UNMAPPED',
      r is None and ref2 in be2.closed and (plan.items[0] if plan.items else {}).get('completion_status')
      == TC.COMPLETION_STATUS_UNMAPPED and TC.level_of(led2[ck]) == TC.COMPLETION_L2_FINAL, plan.items)

    # L3: level 2 by rescan.
    for label, inv, want in (('with the path inventory (qualifying)', True, True),
                             ('without it (not qualifying)', False, False)):
        be3 = RT.RecordingBackend()
        ref3 = _new_ticket(be3, ck)
        led3 = {ck: {'ref': ref3, 'member_identities': ['id-l'],
                     'members': {'id-l': [{'scanner': 'trivy', 'path': 'go.mod', 'scan_scope': ''}]}}}
        doc = {'rows': [{'scanner': 'trivy', 'scope': '', 'established': True, 'gate': 'PASS', 'execution': 'COMPLETE'}]}
        if inv:
            doc['path_inventory'] = {'state': TC.PATH_INVENTORY_ESTABLISHED, 'paths': ['go.mod']}
        r, plan = closure(be3, led3, ck, ref3, 'verify', 'dev-one', 'sec-two', kind='scan', run_id=9,
                          evidence=lambda rid, any_branch=False, d=doc: ({'id': rid, 'head_branch': 'main'}, [], d, None))
        got = TC.level_of(led3[ck]) == TC.COMPLETION_L2_FINAL
        c('L3 level 2 by rescan %s' % label, got == want and ((ref3 in be3.closed) == want) and
          (want or (r is not None and TC.RESCAN_PATH_STATE_NOT_ESTABLISHED in json.dumps(r))), (r, led3[ck]))


# ── R: the qualifying rescan ──────────────────────────────────────────────────────────────

def _entry(**obs):
    o = {'scanner': 'trivy', 'path': 'svc/go.mod', 'scan_scope': 'svc', 'config_sha256': 'a' * 64}
    o.update(obs)
    o = dict((k, v) for k, v in o.items() if v is not None)
    return {'member_identities': ['id-r'], 'members': {'id-r': [o]}}


def _doc(paths=('svc/go.mod',), **row):
    r = {'scanner': 'trivy', 'scope': 'svc', 'established': True, 'gate': 'PASS', 'execution': 'COMPLETE',
         'config_sha256': 'a' * 64}
    r.update(row)
    d = {'rows': [r]}
    if paths is not None:
        d['path_inventory'] = {'state': TC.PATH_INVENTORY_ESTABLISHED, 'paths': list(paths)}
    return d


def claims_r(c):
    good = TC.qualify_rescan(_entry(), [], _doc())
    c('R1 same instance absent, the scanner completed, the file present and in scope, same scope and config: '
      'RESCAN_QUALIFYING', good['verdict'] == TC.RESCAN_QUALIFYING and not good['reasons'], good)
    cases = (
        ('the instance still reported', _entry(), ['id-r'], _doc(), TC.RESCAN_INSTANCE_STILL_PRESENT),
        ('no coverage record (missing scanner output)', _entry(), [], None, TC.RESCAN_OUTPUT_MISSING),
        ('the scanner has no row', _entry(), [], _doc(scanner='grype'), TC.RESCAN_SCANNER_NOT_RUN),
        ('the scanner failed', _entry(), [], _doc(established=False, execution='FAILED', gate='FAILED'),
         TC.RESCAN_SCANNER_NOT_COMPLETED),
        ('the scanner was PARTIAL', _entry(), [], _doc(gate='PARTIAL'), TC.RESCAN_SCANNER_NOT_COMPLETED),
        ('the file was deleted', _entry(), [], _doc(paths=('svc/other.go',)), TC.RESCAN_PATH_REMOVED),
        ('the path is newly excluded', _entry(), [], _doc(excluded=['svc']), TC.RESCAN_PATH_EXCLUDED),
        ('the scope moved elsewhere', _entry(), [], _doc(scope='web'), TC.RESCAN_PATH_OUT_OF_SCOPE),
        ('the scope widened (comparable scope changed)', _entry(), [], _doc(scope=''), TC.RESCAN_SCOPE_CHANGED),
        ('the scanner config changed', _entry(), [], _doc(config_sha256='b' * 64), TC.RESCAN_CONFIG_CHANGED),
        ('the scope at observation not recorded', _entry(scan_scope=None), [], _doc(), TC.RESCAN_BASIS_NOT_RECORDED),
        ('no path inventory', _entry(), [], _doc(paths=None), TC.RESCAN_PATH_STATE_NOT_ESTABLISHED),
        ('the ledger never recorded the instance', {'member_identities': ['id-r'], 'members': {}}, [], _doc(),
         TC.RESCAN_INSTANCE_NOT_RECORDED))
    for label, e, present, doc, want in cases:
        v = TC.qualify_rescan(e, present, doc)
        c('R1 %s: RESCAN_NOT_VERIFIED naming %s' % (label, want),
          v['verdict'] == TC.RESCAN_NOT_VERIFIED and want in [x['reason'] for x in v['reasons']], v['reasons'])

    # R2: the reconciler's own clearance.
    PTL = _ptl()

    def clear(cov2, label):
        tr = PTL.Jira(RT)
        led = {}
        rec = PTL.obs('trivy', 'CVE-R2', 'go.mod', 'id-r2', ['cve-r2'])
        _quiet(PTL.run, RT, tr, [rec], led, '2026-10-01', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        ref = PTL.only_ref(led)
        res = _quiet(PTL.run, RT, tr, [], led, '2026-10-02', PTL.ctx(PTL.RUN2, coverage=cov2))
        return tr, ref, res, next(iter(led.values()))

    def with_inv(cv, paths):
        m = RT.CoverageMap(cv)
        m.path_inventory = {'state': TC.PATH_INVENTORY_ESTABLISHED, 'paths': list(paths)}
        return m
    tr, ref, res, e = clear(with_inv(PTL.cov(trivy=True), ['other.txt']), 'removed')
    c('R2 the reconciler: the affected file was deleted -> nothing closes, RESCAN_PATH_REMOVED named',
      not tr.closed(ref) and TC.RESCAN_PATH_REMOVED in json.dumps(res.get('potentially_absent')),
      res.get('potentially_absent'))
    tr, ref, res, e = clear(with_inv(PTL.cov(trivy={'excluded': ['go.mod']}), ['go.mod']), 'excluded')
    c('R2 the reconciler: the affected path is newly excluded -> nothing closes, RESCAN_PATH_EXCLUDED named',
      not tr.closed(ref) and TC.RESCAN_PATH_EXCLUDED in json.dumps(res.get('potentially_absent')),
      res.get('potentially_absent'))
    tr, ref, res, e = clear(with_inv(PTL.cov(trivy=True), ['go.mod']), 'full')
    c('R2 the reconciler: a full qualifying rescan closes and FINALISES (level 2 by rescan)',
      tr.closed(ref) and TC.level_of(e) == TC.COMPLETION_L2_FINAL and
      ((e.get('completion') or {}).get('level2') or {}).get('by') == 'rescan', e.get('completion'))
    tr, ref, res, e = clear(PTL.cov(trivy=True), 'no inventory')
    c('R2 the reconciler: without a path inventory the ticket closes as before but is NOT finalised (named)',
      tr.closed(ref) and TC.level_of(e) != TC.COMPLETION_L2_FINAL and
      TC.RESCAN_PATH_STATE_NOT_ESTABLISHED in json.dumps(e.get('completion_rescan')), e.get('completion_rescan'))


# ── X: recurrence after level 2 ───────────────────────────────────────────────────────────

def claims_x(c):
    PTL = _ptl()
    for T in PTL.TRACKERS:
        tr = T(RT)
        led = {}
        rec = PTL.obs('trivy', 'CVE-X1', 'go.mod', 'id-x1', ['cve-x1'])
        _quiet(PTL.run, RT, tr, [rec], led, '2026-10-01', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        ref = PTL.only_ref(led)
        cv = RT.CoverageMap(PTL.cov(trivy=True))
        cv.path_inventory = {'state': TC.PATH_INVENTORY_ESTABLISHED, 'paths': ['go.mod']}
        _quiet(PTL.run, RT, tr, [], led, '2026-10-02', PTL.ctx(PTL.RUN2, coverage=cv))
        key = next(iter(led))
        final = TC.level_of(led[key]) == TC.COMPLETION_L2_FINAL
        res = _quiet(PTL.run, RT, tr, [rec], led, '2026-10-03', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        e = led[key]
        new = str(e.get('ref') or '')
        rc = [x for x in e.get('recurrences') or [] if x.get('after_final')]
        c('X1 %s after level 2 the finding returns: a NEW linked ticket naming its predecessor, never a reopen'
          % tr.name, final and new and new != str(ref) and tr.closed(ref) and not tr.closed(new) and
          len(rc) == 1 and rc[0]['predecessor'] == str(ref) and rc[0]['number'] == 1 and
          any(str(ref) in b for b in [tr.body(new)]), (final, ref, new, rc))
        c('X1 %s the history is kept: the predecessor\'s level 2 is in completion_history, the predecessor listed'
          % tr.name, [h.get('level') for h in e.get('completion_history') or []] == [TC.COMPLETION_L2_FINAL] and
          str(ref) in (e.get('predecessors') or []) and not e.get('completion'), e.get('completion_history'))
        n_before = len(tr.tickets())
        _quiet(PTL.run, RT, tr, [rec], led, '2026-10-04', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
        c('X1 %s deterministic: the next run binds the recurrence ticket and creates nothing more' % tr.name,
          len(tr.tickets()) == n_before and str(led[key].get('ref')) == new and
          len([x for x in led[key].get('recurrences') or [] if x.get('after_final')]) == 1,
          (n_before, len(tr.tickets())))
    # Before level 2 (closed, not final): the existing RECURRED reopen policy is unchanged.
    tr = PTL.Jira(RT)
    led = {}
    rec = PTL.obs('trivy', 'CVE-X2', 'go.mod', 'id-x2', ['cve-x2'])
    _quiet(PTL.run, RT, tr, [rec], led, '2026-10-01', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
    ref = PTL.only_ref(led)
    _quiet(PTL.run, RT, tr, [], led, '2026-10-02', PTL.ctx(PTL.RUN2, coverage=PTL.cov(trivy=True)))
    res = _quiet(PTL.run, RT, tr, [rec], led, '2026-10-03', PTL.ctx(PTL.RUN1, coverage=PTL.cov(trivy=True)))
    c('X1 not final: the existing policy reopens the same ticket (RECURRED), no new ticket',
      not tr.closed(ref) and PTL.only_ref(led) == ref and
      [x.get('classification') for x in res.get('reopened') or []] == ['RECURRED'], res.get('reopened'))


def claims_p(c):
    import shutil
    import subprocess
    import tempfile
    import scan_report as SR
    d = tempfile.mkdtemp(prefix='kit-levels-inv-')
    try:
        io.open(os.path.join(d, 'go.mod'), 'w', encoding='utf-8').write('module x\n')
        os.makedirs(os.path.join(d, 'svc'))
        io.open(os.path.join(d, 'svc', 'a.py'), 'w', encoding='utf-8').write('x = 1\n')
        ok = subprocess.run(['git', 'init', '-q', d], capture_output=True).returncode == 0 and \
            subprocess.run(['git', '-C', d, 'add', '-A'], capture_output=True).returncode == 0
        inv = SR.path_inventory(d) if ok else {}
        c('P1 a git checkout: PATH_INVENTORY_ESTABLISHED with every tracked file',
          inv.get('state') == SR.PATH_INVENTORY_ESTABLISHED == TC.PATH_INVENTORY_ESTABLISHED and
          inv.get('paths') == ['go.mod', 'svc/a.py'] and inv.get('count') == 2, inv)
        plain = tempfile.mkdtemp(prefix='kit-levels-plain-')
        try:
            c('P1 no checkout, or a directory git cannot list: PATH_INVENTORY_NOT_ESTABLISHED, no paths',
              SR.path_inventory('').get('state') == SR.PATH_INVENTORY_NOT_ESTABLISHED and
              'paths' not in SR.path_inventory('') and
              SR.path_inventory(os.path.join(plain, 'missing')).get('state') == SR.PATH_INVENTORY_NOT_ESTABLISHED,
              SR.path_inventory(''))
        finally:
            shutil.rmtree(plain, ignore_errors=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def claims(_work=None):
    out = []

    def c(label, ok, detail=''):
        out.append((label, bool(ok), detail))
    for fn in (claims_o, claims_c, claims_t, claims_l, claims_r, claims_p, claims_x):
        try:
            fn(c)
        except Exception as exc:                     # noqa: BLE001 - a crash is a failed claim, named
            import traceback
            out.append(('%s crashed' % fn.__name__.replace('claims_', '').upper(), False,
                        '%s: %s %s' % (type(exc).__name__, exc, traceback.format_exc()[-600:])))
    return out


def swap_function(mod, name, old, new):
    fn = getattr(mod, name)
    src = inspect.getsource(fn)
    if src.count(old) != 1:
        raise SystemExit('mutant anchor not in %s.%s exactly once: %r' % (mod.__name__, name, old))
    ns = {}
    exec(compile(src.replace(old, new), mod.__file__ + ' (mutant)', 'exec'), mod.__dict__, ns)
    setattr(mod, name, ns[name])
    return lambda: setattr(mod, name, fn)


MUTANTS = [
    ('MX1 the instance overflow is not escalated', 'O1 the instance overflow',
     lambda: swap_function(RT, 'ceiling_overflow', 'if escalate and', 'if False and')),
    ('MX2 the duplicate closes with the register unread', 'C1 register NOT',
     lambda: swap_function(TSUB, '_plan_exact', 'hold = continuity_hold(rec0)', 'hold = None')),
    ('MX3 the level-1 actor may set level 2', 'L2 the recorded level-1 actor',
     lambda: swap_function(TC, 'set_level2', 'if _same_actor(actor, l1a) or _same_actor(actor, fallback_l1_actor):',
                           'if False:')),
    ('MX4 a removed file is not a disqualifier', 'R1 the file was deleted',
     lambda: swap_function(TC, 'qualify_rescan', "elif path and _norm(path) not in paths:", "elif False:")),
    ('MX5 recurrence after level 2 reopens the final ticket', 'X1 jira after level 2',
     lambda: swap_function(TC, 'plan_recurrence', 'if level_of(entry) != COMPLETION_L2_FINAL:', 'if True:')),
    ('MX6 a level label decides the level', 'T3 ',
     lambda: swap_function(TC, 'level_of', "lv = (c or {}).get('level') if isinstance(c, dict) else None",
                           "lv = COMPLETION_L2_FINAL")),
]


def main():
    fails = []
    for label, ok, detail in claims():
        print('  %s %s' % ('ok  ' if ok else 'FAIL', label))
        if not ok:
            fails.append('%s -- %s' % (label, json.dumps(detail, default=str)[:900]))
    passed = len(claims()) - len(fails) if not fails else None
    for label, prefix, apply in MUTANTS:
        try:
            undo = apply()
        except SystemExit as exc:
            fails.append('mutant %s could not be applied: %s' % (label, exc))
            continue
        try:
            got = [x for x in claims() if x[0].startswith(prefix) and not x[1]]
        finally:
            undo()
        print('  mutant %-58s %s' % (label, ('caught at %s' % got[0][0][:60]) if got else 'NOT CAUGHT'))
        if not got:
            fails.append('mutant %s was not caught at %s' % (label, prefix))
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        print('::error title=Ticket levels unproven::%d failure(s)' % len(fails))
        return 1
    print('PASS (%s claims, %d mutants caught): overflow escalated with nothing truncated; no automatic duplicate '
          'closure, clearance or risk carry-forward without the register; a person\'s label survives; a level label '
          'decides nothing; level 2 never by the level-1 actor; only a qualifying rescan; a recurrence after level 2 '
          'is a new linked ticket.' % (passed, len(MUTANTS)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
