#!/usr/bin/env python3
"""Ticket intake v2: the owner's rulings of 2026-11-04 on the KDEC-037 build (recorded in KDEC-037).

CASES (each a refusal or a hold by name AND its allowed counterpart, docs/PROOF_RULE.md)
    V1  separation of duties: nobody approves what they authored -- the review they submitted, the AI
        run they started, the triage they decided, the request they made; another member may concur on
        the AI's work that ran for another engineer; a DISAGREE sends the items back with the dissent
        recorded, and an item-level DISAGREE sends back only that item
    V2  approvers: the whole security list, from a list file or a GitHub team; a non-member is refused;
        a team that cannot be read is not a list
    V3  closure: the fixer resolves -> PENDING VERIFICATION and the approver list is tapped; the fixer
        "verifying" stays pending; another person verifies -> closed; a rejection reopens; the clock
        reminds once at 7 days and escalates once at 14
    V4  branches: a clean scan on a feature branch records "fix observed on <branch>" and closes
        nothing; a clean scan on the branch mapped to the ticket's environment closes it
    V5  dedupe: an exact match is a CLOSED DUPLICATE under the original, which is told what it added
        (a new source: confidence X -> Y); the same contribution twice adds nothing; a closed original
        newly observed is a REGRESSION; a near match is CREATED, flagged and queued for triage, and a
        triage decision merges or separates it; a search that did not complete creates the ticket as
        DEDUPE PENDING and the next run re-runs its dedupe; an unreachable tracker goes to the OUTBOX,
        is alerted, and is drained by the next run; NO INPUT ITEM EVER DISAPPEARS
    V6  trust beside confidence: deterministic, by source class, evidence integrity, identity, review
        and custody; both on the ticket and in the answer
    V7  the taxonomy: false positive (evidence, no expiry, re-checked on a tool change), exception (at
        most 90 days, a specific scope, compensating controls), exemption (a review cadence), accepted
        risk (owner, review date, risk register), compliance exception (framework, control, authority);
        the reconciler's exception -> EXCEPTION_REQUEST
    V8  extensions: 30 days by default; a fix available caps at 2; waiting on a vendor continues, with
        the advisory at the second extension
    V9  the no-fix clock: a re-check every 30 days, a review every 90, the advisory at 180 (earlier and
        escalated for critical/high; none for low)
    V10 proposed ticket types are listed, stubbed and DISABLED (TEMPLATE_NOT_ENABLED)
    V11 the Azure DevOps and GitHub Issues intake adapters: search-first, exact and near, paged, and a
        duplicate record that never carries the original's stamp

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

FAILS = []
REVIEWER, OTHER = 'security-reviewer', 'other-reviewer'
TODAY = '2026-11-04'
P = 'secure-cicd-kit'


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def imports():
    try:
        import prove_ticket_templates as pt
        mods = pt.imports()
        import ticket_intake as ti
        import separation_of_duties as sod
        return pt, mods, ti, sod
    except (ImportError, AttributeError) as exc:
        print('FAIL: cannot import the v2 machinery (%s)' % exc)
        return None


class V(object):
    """prove_ticket_templates' world, with v2 review records."""

    def __init__(self, pt, mods, tmp, **kw):
        self.pt = pt
        os.makedirs(tmp, exist_ok=True)
        self.x = pt.W(mods, tmp, **kw)
        self.tt, self.tb, self.rt, self.fc = mods[5], mods[3], mods[2], mods[6]
        self.t = self.x.t
        self.x.w.env['KIT_API_TODAY'] = TODAY
        self.n = 0

    def finalize(self, params, concurred_by=REVIEWER, **kw):
        self.n += 1
        return self.x.finalize('USR-V2-%03d' % self.n, params, concurred_by=concurred_by, **kw)

    def submit(self, params, dry=False, **kw):
        self.n += 1
        return self.x.submit(self.finalize(params, **kw) if kw.pop('review', True) else params,
                             'v2-key-%06d' % self.n, dry_run=dry)[0]

    def raw(self, params, dry=False):
        self.n += 1
        return self.x.submit(params, 'v2-raw-key-%06d' % self.n, dry_run=dry)[0]

    def labels(self, ref):
        return self.t.issues[str(ref)]['fields']['labels']

    def status(self, ref):
        return (self.t.status_of(str(ref)).get('statusCategory') or {}).get('key')

    def comments(self, ref):
        return [c for i, c in self.t.comments if i == str(ref)]


def items(res):
    return (res.get('data') or {}).get('items') or []


def outcome(res, n=0):
    it = items(res)
    return it[n].get('outcome') if len(it) > n else None


def codes(res):
    return (res.get('refusal') or {}).get('code'), ((res.get('data') or {}).get('template_refusal') or {}).get('code')


def F(tt, **over):
    return tt.example_finding(**over)


def fparams(tt, *fs):
    return {'template': 'finding', 'template_version': 2, 'items': list(fs)}


# ── V1 ─────────────────────────────────────────────────────────────────────────────────────

def v1(pt, mods, ti, sod, tmp):
    tt = mods[5]
    for label, kw in (('the submitter', {'submitted_by': REVIEWER}),
                      ('the engineer who started the AI run', {'run_started_by': REVIEWER}),
                      ('the triager', {'triaged_by': REVIEWER})):
        v = V(pt, mods, os.path.join(tmp, re.sub(r'\W', '', label)))
        res = v.submit(fparams(tt, F(tt)), **kw)
        check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED' and not v.t.issues and
              'SOD' in json.dumps((res.get('data') or {}).get('review')),
              'V1 %s concurring was %r with %d ticket(s)' % (label, codes(res), len(v.t.issues)))
    # The requester of an exception may not approve it.
    v = V(pt, mods, os.path.join(tmp, 'req'))
    exc = {'finding': F(tt), 'justification': 'parameterised traffic the WAF misreads as an injection',
           'scope': {'from': 'partner-gateway', 'to': '/api/orders', 'condition': 'rule 942100 on POST'},
           'compensating_controls': ['schema validation on the endpoint'], 'expires': '2026-12-31',
           'requested_by': REVIEWER, 'evidence': F(tt)['evidence']}
    res = v.submit({'template': 'exception', 'template_version': 2, 'items': [exc]})
    check(codes(res) == ('API_TEMPLATE_RULE_REFUSED', 'SOD_SELF_APPROVAL') and not v.t.issues,
          'V1 the requester approving their own exception was %r' % (codes(res),))
    # Another member concurs on the AI's work that ran for another engineer: allowed.
    v = V(pt, mods, os.path.join(tmp, 'ok'))
    res = v.submit(fparams(tt, F(tt)), run_started_by='engineer-one', triaged_by='engineer-one')
    check(outcome(res) == tt.TEMPLATE_TICKET_CREATED and len(v.t.issues) == 1,
          'V1 another member concurring on an AI run for another engineer was refused: %r %r' % (codes(res), items(res)))
    # DISAGREE with an alternative: nothing written, every item sent back, the dissent recorded.
    v = V(pt, mods, os.path.join(tmp, 'dis'))
    res = v.submit(fparams(tt, F(tt), F(tt, identifier='OTHER-RULE-1')), decision='DISAGREE',
                   alternative='the TLS finding is a duplicate of last quarter\'s audit item; re-check the scope')
    dis = (res.get('data') or {}).get('dissent') or []
    check(res.get('api_state') == 'API_COMPLETED' and not v.t.issues and
          all(i.get('outcome') == tt.TEMPLATE_SENT_BACK for i in items(res)) and len(items(res)) == 2 and
          dis and 'last quarter' in dis[0].get('alternative', ''),
          'V1 a DISAGREE did not send everything back with the dissent: %r %r' % (items(res), dis))
    res = v.submit(fparams(tt, F(tt)), decision='DISAGREE')
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED',
          'V1 a DISAGREE with no alternative was %r' % (codes(res),))
    # An item-level DISAGREE sends back only that item.
    res = v.submit(fparams(tt, F(tt), F(tt, identifier='OTHER-RULE-1')),
                   item_decisions=[{'item': 1, 'decision': 'DISAGREE', 'alternative': 'not reproducible'}])
    oc = sorted(i.get('outcome') for i in items(res))
    check(oc == sorted([tt.TEMPLATE_TICKET_CREATED, tt.TEMPLATE_SENT_BACK]) and len(v.t.issues) == 1,
          'V1 an item-level DISAGREE did not send back only that item: %r' % oc)
    # The SoD module itself: every author role is refused, a non-author is allowed.
    roles = {'submitter': 'a', 'run_started_by': 'b', 'triager': 'c', 'fixer': 'd', 'requester': 'e'}
    for who in 'abcde':
        check(sod.violations(roles, who), 'V1 SoD allowed %s to approve their own work' % who)
    check(not sod.violations(roles, 'f'), 'V1 SoD refused a person who authored nothing')
    check(sod.violations({}, 'tines-kit-app[bot]') and sod.violations(roles, 'A@Example.com'),
          'V1 SoD let a bot concur, or missed an author by e-mail form')


# ── V2 ─────────────────────────────────────────────────────────────────────────────────────

def v2(pt, mods, ti, sod, tmp):
    tt = mods[5]
    v = V(pt, mods, tmp)
    v.x.w.env['KIT_API_REVIEW_APPROVER_SOURCE'] = 'team:octo-org/security-review'
    v.x.w.stub.teams = {('octo-org', 'security-review'): [REVIEWER, OTHER, 'third-reviewer']}
    res = v.submit(fparams(tt, F(tt)), concurred_by='third-reviewer')
    check(outcome(res) == tt.TEMPLATE_TICKET_CREATED, 'V2 a team member\'s concurrence was refused: %r' % (codes(res),))
    res = v.submit(fparams(tt, F(tt, identifier='RULE-B')), concurred_by='not-on-team')
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED', 'V2 a non-member concurred')
    v.x.w.stub.fail[('GET', r'/teams/')] = 403
    res = v.submit(fparams(tt, F(tt, identifier='RULE-C')))
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED' and
          'team' in json.dumps((res.get('data') or {}).get('review')).lower(),
          'V2 an unreadable team was read as a list: %r' % (codes(res),))
    v.x.w.stub.fail.clear()
    # ONE MECHANISM (KDEC-036 + KDEC-037): the security team's list sits in the same approver_lists structure as
    # KDEC-036's AppSec list -- in the central register, or in the shared file its approver_lists_source names.
    v = V(pt, mods, os.path.join(tmp, 'shared'))
    reg = os.path.join(tmp, 'shared', 'central.json')
    io.open(os.path.join(tmp, 'shared', 'approver-lists.json'), 'w', encoding='utf-8').write(json.dumps(
        {'approver_lists': {'appsec': ['appsec-one'], 'review-concurrence': ['shared-list-reviewer']}}))
    io.open(reg, 'w', encoding='utf-8').write(json.dumps({'schema_version': 1, 'approver_lists_source': 'approver-lists.json'}))
    v.x.w.env['KIT_API_CENTRAL_REGISTRATION'] = reg
    v.x.w.env['KIT_API_REVIEW_APPROVER_SOURCE'] = 'list:review-concurrence'
    res = v.submit(fparams(tt, F(tt, identifier='RULE-SHARED')), concurred_by='shared-list-reviewer')
    check(outcome(res) == tt.TEMPLATE_TICKET_CREATED,
          'V2 a member of the shared approver_lists file (approver_lists_source) was refused: %r %r' % (
              codes(res), ((res.get('data') or {}).get('review') or {}).get('reasons')))
    res = v.submit(fparams(tt, F(tt, identifier='RULE-SHARED-2')), concurred_by='appsec-one')
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED',
          'V2 a member of ANOTHER list (appsec) concurred as the security team')


# ── V3 ─────────────────────────────────────────────────────────────────────────────────────

def _seed(v, tt, **over):
    res = v.submit(fparams(tt, F(tt, **over)))
    return (items(res) or [{}])[0].get('ref')


def closure(tt, ref, action, kind='reviewer', fixer='dev-one', **more):
    item = dict({'ref': ref, 'action': action, 'requested_by': fixer, 'fixed_by': fixer,
                 'evidence': {'ref': 'pull/88', 'sha256': 'd' * 64}, 'verification': {'kind': kind}}, **more)
    return {'template': 'closure', 'template_version': 2, 'items': [item]}


def v3(pt, mods, ti, sod, tmp):
    tt, rt, tb = mods[5], mods[2], mods[3]
    v = V(pt, mods, tmp)
    ref = _seed(v, tt)
    if not check(ref, 'V3 no seed ticket'):
        return
    res = v.raw(closure(tt, ref, 'resolve'))
    notes = (res.get('data') or {}).get('notifications') or []
    check(outcome(res) == tt.TEMPLATE_PENDING_VERIFICATION and v.status(ref) != 'done' and
          '%s-pending-verification' % P in v.labels(ref) and notes and 'review-concurrence' in notes[0].get('to', '') and
          any('please verify' in c.lower() for c in v.comments(ref)),
          'V3 the fixer\'s resolve did not go pending with the approver list tapped: %r %r' % (items(res), notes))
    res = v.submit(closure(tt, ref, 'verify'), concurred_by='dev-one')
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED' or
          (outcome(res) == tt.TEMPLATE_PENDING_VERIFICATION and v.status(ref) != 'done'),
          'V3 the fixer verifying their own fix closed it: %r %r' % (codes(res), v.status(ref)))
    res = v.submit(closure(tt, ref, 'verify', fixer=REVIEWER))
    check(outcome(res) == tt.TEMPLATE_PENDING_VERIFICATION and v.status(ref) != 'done',
          'V3 a concurrer who is the fixer closed the ticket instead of leaving it pending: %r' % items(res))
    res = v.submit(closure(tt, ref, 'reject', reason='the fix only covers one of the two endpoints'))
    check(outcome(res) == tt.TEMPLATE_VERIFICATION_REJECTED and
          any('REJECTED' in c for c in v.comments(ref)), 'V3 a rejection was %r' % items(res))
    v.raw(closure(tt, ref, 'resolve'))
    res = v.submit(closure(tt, ref, 'verify'))
    check(outcome(res) == tt.TEMPLATE_TICKET_CLOSED and v.status(ref) == 'done' and
          '%s-verified' % P in v.labels(ref), 'V3 another person\'s verification did not close it: %r' % items(res))
    # The clock: a pending ticket is reminded once at 7 days and escalated once at 14.
    ref2 = _seed(v, tt, identifier='RULE-CLOCK')
    v.raw(closure(tt, ref2, 'resolve'))
    for day in ('2026-11-08', '2026-11-11', '2026-11-12', '2026-11-18', '2026-11-19'):
        rt.resurface({}, rt.choose_backend(tb.JIRA_ENV)[0], True, day)
    rem = [c for c in v.comments(ref2) if 'VERIFICATION REMINDER' in c]
    esc = [c for c in v.comments(ref2) if 'VERIFICATION ESCALATED' in c]
    check(len(rem) == 1 and len(esc) == 1, 'V3 the clock reminded %d and escalated %d time(s), expected 1 and 1'
          % (len(rem), len(esc)))


# ── V4 ─────────────────────────────────────────────────────────────────────────────────────

def v4(pt, mods, ti, sod, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    v = V(pt, mods, tmp)
    obs = v.x.w.findings
    fpath, cpath = os.path.join(tmp, 'f.json'), os.path.join(tmp, 'findings-coverage.json')
    io.open(fpath, 'w', encoding='utf-8').write(json.dumps(obs))
    io.open(cpath, 'w', encoding='utf-8').write(json.dumps(ps.COVERAGE))
    ps._pipeline(rt, dict(tb.JIRA_ENV, JIRA_TRANSITION_REOPEN='Reopen'), fpath, v.x.w.ledger, cpath)
    led = ps.read_ledger(v.x.w.ledger)
    key = [k for k, e in led.items() if 'a1' * 16 in (e.get('member_identities') or [])]
    if not check(key, 'V4 the pipeline did not ticket the kit finding'):
        return
    ref = led[key[0]]['ref']
    fixed = [o for o in obs if o['identity'] != 'a1' * 16]
    feat = v.x.w.stub.add_run(workflow='build-deploy.yml', branch='feature/fix-log4j', head_sha='e' * 40)
    v.x.w.stub.add_artifact(feat, 'security-report-1', {'findings.json': json.dumps(fixed),
                                                        'findings-coverage.json': json.dumps(ps.COVERAGE)})
    res = v.raw(closure(tt, ref, 'verify', kind='scan', verification={'kind': 'scan', 'run_id': feat}))
    check(outcome(res) == tt.TEMPLATE_FIX_OBSERVED and v.status(ref) != 'done' and
          any('feature/fix-log4j' in c for c in v.comments(ref)),
          'V4 a clean feature-branch scan did not record the fix observed (or closed it): %r' % items(res))
    main = v.x.w.stub.add_run(workflow='build-deploy.yml', head_sha='f' * 40)
    v.x.w.stub.add_artifact(main, 'security-report-1', {'findings.json': json.dumps(fixed),
                                                        'findings-coverage.json': json.dumps(ps.COVERAGE)})
    res = v.raw(closure(tt, ref, 'verify', kind='scan', verification={'kind': 'scan', 'run_id': main}))
    check(outcome(res) == tt.TEMPLATE_TICKET_CLOSED and v.status(ref) == 'done',
          'V4 a clean scan on the mapped branch did not close it: %r' % items(res))
    check(tt.branch_environment('main', 'main=prod,dev=dev,test=test', 'main') == 'prod' and
          tt.branch_environment('feature/x', 'main=prod,dev=dev', 'main') is None and
          tt.branch_environment('release/2026.11', 'main=prod,release/*=Azure Government Prod', 'main') ==
          'azure-government-prod' and tt.branch_environment('main', '', 'main') == 'prod',
          'V4 the branch -> environment mapping is wrong')


# ── V5 ─────────────────────────────────────────────────────────────────────────────────────

TERMINAL = None


def v5(pt, mods, ti, sod, tmp):
    tt, rt, tb = mods[5], mods[2], mods[3]
    global TERMINAL
    TERMINAL = set(tt.TERMINAL_OUTCOMES)
    v = V(pt, mods, os.path.join(tmp, 'a'))
    ref = _seed(v, tt, source_tool='defender')
    if not check(ref, 'V5 no seed ticket'):
        return
    n_before = len(v.t.issues)
    res = v.submit(fparams(tt, F(tt, source_tool='prowler', source_type='usr', severity='critical',
                                evidence={'ref': 'usr/2', 'sha256': '7' * 64})))
    it = (items(res) or [{}])[0]
    dups = [i for i in v.t.issues.values() if int(i['id']) > int(ref)]
    check(it.get('outcome') == tt.TEMPLATE_CLOSED_DUPLICATE and it.get('original_ref') == ref and len(dups) == 1 and
          (dups[0]['fields']['status'].get('statusCategory') or {}).get('key') == 'done' and
          not dups[0]['fields'].get('customfield_10001'),
          'V5 an exact match was not a closed, unstamped duplicate under the original: %r %d' % (it, len(dups)))
    added = ' '.join(v.comments(ref))
    check(re.search(r'confidence increased \d+ -> \d+', added) and 'prowler' in added and '7' * 16 in added and
          'severity' in added.lower(), 'V5 the original was not told what the duplicate added: %r' % added[-400:])
    res = v.submit(fparams(tt, F(tt, source_tool='prowler', source_type='usr', severity='critical',
                                evidence={'ref': 'usr/2', 'sha256': '7' * 64})))
    check(outcome(res) in (tt.TEMPLATE_TICKET_BOUND, tt.TEMPLATE_LINKED_EXACT) and len(v.t.issues) == n_before + 1,
          'V5 the same contribution twice made another record: %r' % items(res))
    # A closed original, newly observed: a REGRESSION, not a duplicate.
    v.t.issues[ref]['fields']['status'] = {'name': 'Done', 'statusCategory': {'key': 'done'}}
    res = v.submit(fparams(tt, F(tt, source_tool='wiz', source_type='resource',
                                evidence={'ref': 'wiz/9', 'sha256': '8' * 64})))
    check(outcome(res) == tt.TEMPLATE_REGRESSION and v.status(ref) != 'done' and
          '%s-regression' % P in v.labels(ref), 'V5 a closed original newly observed was %r' % items(res))
    # A near match: CREATED, flagged, in triage; never merged.
    v = V(pt, mods, os.path.join(tmp, 'b'))
    f = F(tt)
    manual = pt.manual_ticket(tb, v.t, 'TLS 1.0 still enabled on acct1', 'audit: %s allows TLS 1.0 (%s)'
                              % (f['asset']['resource_id'], f['identifier']))
    res = v.submit(fparams(tt, f))
    it = (items(res) or [{}])[0]
    new = [i for i in v.t.issues if i != manual]
    check(it.get('outcome') == tt.TEMPLATE_POSSIBLE_DUPLICATE and len(new) == 1 and
          '%s-possible-duplicate' % P in v.labels(new[0]) and '%s-triage' % P in v.labels(new[0]) and
          any(manual in c or ('KIT-%s' % manual) in c for c in v.comments(new[0])),
          'V5 a near match was not created, flagged and queued: %r' % it)
    pd = new[0] if new else None
    if pd:
        res = v.submit({'template': 'triage', 'template_version': 2, 'items': [
            {'ref': pd, 'original_ref': manual, 'decision': 'merge', 'triaged_by': 'engineer-one',
             'reason': 'the audit item is the same storage account and rule'}]})
        check(outcome(res) == tt.TEMPLATE_CLOSED_DUPLICATE and v.status(pd) == 'done',
              'V5 a triage merge did not close the possible duplicate: %r' % items(res))
        res = v.submit({'template': 'triage', 'template_version': 2, 'items': [
            {'ref': pd, 'original_ref': manual, 'decision': 'merge', 'triaged_by': REVIEWER,
             'reason': 'the triager concurring on their own triage'}]})
        check(codes(res) == ('API_TEMPLATE_RULE_REFUSED', 'SOD_SELF_APPROVAL'),
              'V5 the triager approving their own triage was %r' % (codes(res),))
    # A search that did not complete: created as DEDUPE PENDING, then re-run by the next submission.
    v = V(pt, mods, os.path.join(tmp, 'c'), fail_search=True)
    res = v.submit(fparams(tt, F(tt)))
    it = (items(res) or [{}])[0]
    pend = it.get('ref')
    check(it.get('outcome') == tt.TEMPLATE_DEDUPE_PENDING and pend and '%s-dedupe-pending' % P in v.labels(pend),
          'V5 a search that did not complete lost or held the ticket: %r' % it)
    pt.install_intake_search(tb, v.t, v.x.replay, fail=False)
    res = v.submit(fparams(tt, F(tt, identifier='UNRELATED-1')))
    redo = (res.get('data') or {}).get('dedupe_rechecked') or []
    check(pend and '%s-dedupe-done' % P in v.labels(pend) and redo,
          'V5 the next run did not re-run the pending dedupe: %r' % redo)
    # An unreachable tracker: the OUTBOX, alerted; the next run drains it.
    v = V(pt, mods, os.path.join(tmp, 'd'))
    v.x.w.env['JIRA_HOST'] = 'https://unreachable.invalid'
    v.x.replay.on('GET', r'unreachable\.invalid', lambda rec: (503, {'errorMessages': ['down']}, {}))
    v.x.replay.on('POST', r'unreachable\.invalid', lambda rec: (503, {'errorMessages': ['down']}, {}))
    res = v.submit(fparams(tt, F(tt), F(tt, identifier='RULE-OUT-2')))
    ob = (res.get('data') or {}).get('outbox') or {}
    out_dirs = [d for d, _s, fs in os.walk(os.path.join(tmp, 'd')) if 'outbox.json' in fs]
    check(all(i.get('outcome') == tt.TEMPLATE_OUTBOX for i in items(res)) and len(items(res)) == 2 and
          ob.get('entries') == 2 and (res.get('data') or {}).get('alerts') and out_dirs,
          'V5 an unreachable tracker did not put both items in the outbox with an alert: %r %r' % (items(res), ob))
    if out_dirs:
        blob = io.open(os.path.join(out_dirs[0], 'outbox.json'), encoding='utf-8').read()
        rid = max(r['id'] for r in v.x.w.stub.runs.values() if r['workflow'] == 'kit-api.yml')
        v.x.w.stub.add_artifact(rid, 'kit-ticket-outbox-%s' % json.loads(blob)['correlation_id'], {'outbox.json': blob})
    v.x.w.env['JIRA_HOST'] = 'https://example.atlassian.net'
    res = v.submit(fparams(tt, F(tt, identifier='RULE-AFTER')))
    drained = (res.get('data') or {}).get('outbox_drained') or []
    check(drained and len(v.t.issues) == 3, 'V5 the next run did not drain the outbox: %r, %d ticket(s)'
          % (drained, len(v.t.issues)))
    # NO INPUT ITEM EVER DISAPPEARS: across tracker states and candidates, every item ends in a terminal state.
    for state in ('healthy', 'search-fails', 'create-fails', 'unreachable'):
        for cand in ('none', 'exact', 'near'):
            d = os.path.join(tmp, 'm-%s-%s' % (state, cand))
            os.makedirs(d)
            v = V(pt, mods, d, fail_search=(state == 'search-fails'))
            f = F(tt, identifier='MATRIX-%s-%s' % (state[:3], cand))
            if cand == 'exact':
                _seed(v, tt, identifier=f['identifier'])
            if cand == 'near':
                pt.manual_ticket(tb, v.t, 'manual', 'about %s and %s' % (f['asset']['resource_id'], f['identifier']))
            if state == 'create-fails':
                v.x.replay.on('POST', r'/rest/api/3/issue$', lambda rec: (500, {'errorMessages': ['x']}, {}))
            if state == 'unreachable':
                v.x.w.env['JIRA_HOST'] = 'https://unreachable.invalid'
                v.x.replay.on('GET', r'unreachable', lambda rec: (503, None, {}))
                v.x.replay.on('POST', r'unreachable', lambda rec: (503, None, {}))
            res = v.submit(fparams(tt, f, F(tt, identifier=f['identifier'] + '-B')))
            got = [i.get('outcome') for i in items(res)]
            check(len(got) == 2 and all(g in TERMINAL for g in got),
                  'V5 no-disappear: %s/%s ended %r (api %s)' % (state, cand, got, res.get('api_state')))


# ── V6 ─────────────────────────────────────────────────────────────────────────────────────

def v6(pt, mods, ti, sod, tmp):
    tt = mods[5]
    base = {'approved_tools': ['defender'], 'evidence_stores': ['usr-reviews/'], 'review_finalized': True,
            'submitter_verified': True}
    kit = tt.trust_score({'job': 'sast-semgrep', 'provenance': {'evidence_sha256': 'a' * 64}, 'row_established': True},
                         dict(base, evidence_verified=True))
    integ = tt.trust_score(tt.normalize('finding', F(tt, source_tool='defender'), {}), base)
    pent = tt.trust_score(tt.normalize('finding', F(tt, source_tool='acme-pentest', source_type='pentest'), {}), base)
    rev = tt.trust_score(tt.normalize('finding', F(tt, source_tool='usr-review', source_type='usr'), {}), base)
    man = tt.trust_score(tt.normalize('finding', F(tt, source_tool='someone', source_type='other-tool'), {}), base)
    seq = [kit[0], integ[0], pent[0], rev[0], man[0]]
    check(seq == sorted(seq, reverse=True) and len(set(seq)) == 5,
          'V6 trust does not order kit scan > integrated > pentest/audit > reviewer > manual: %r' % seq)
    noev = tt.trust_score(tt.normalize('finding', F(tt, source_tool='defender'), {}), dict(base, review_finalized=False))
    check(noev[0] < integ[0] and 'review' in noev[1], 'V6 the review concurrence does not count: %r' % (noev,))
    store = tt.trust_score(tt.normalize('finding', F(tt, source_tool='defender', evidence={
        'ref': 'usr-reviews/x/1.json', 'sha256': 'e' * 64, 'receipt': 'rcpt-123'}), {}), base)
    check(store[0] > integ[0] and 'custody' in store[1] and 'receipt' in store[1],
          'V6 custody and receipt do not count: %r' % (store,))
    check(tt.trust_score(tt.normalize('finding', F(tt), {}), base) == tt.trust_score(tt.normalize('finding', F(tt), {}),
                                                                                     base), 'V6 trust is not deterministic')
    v = V(pt, mods, tmp)
    res = v.submit(fparams(tt, F(tt)))
    it = (items(res) or [{}])[0]
    ref = it.get('ref')
    body = mods[3].adf_text(v.t.issues[ref].get('description')) if ref else ''
    check(isinstance(it.get('trust'), int) and isinstance(it.get('confidence'), int) and it.get('trust_basis') and
          '| trust score |' in body and '| confidence score |' in body,
          'V6 trust and confidence are not both on the ticket and in the answer: %r' % it)


# ── V7 ─────────────────────────────────────────────────────────────────────────────────────

def v7(pt, mods, ti, sod, tmp):
    tt, rt = mods[5], mods[2]
    f = F(tt)
    ev = f['evidence']
    good = {
        'false-positive': {'finding': f, 'justification': 'the rule matches a test fixture, not product code',
                           'requested_by': 'app-team', 'evidence': ev, 'rule_id': 'AZURE-STORAGE-TLS-1-0',
                           'tool_version': '4.2.0', 'code_ref': 'a' * 40},
        'exception': {'finding': f, 'justification': 'parameterised traffic the WAF misreads as an injection',
                      'scope': {'from': 'partner-gateway', 'to': '/api/orders', 'condition': 'rule 942100 on POST'},
                      'compensating_controls': ['schema validation on the endpoint'], 'expires': '2027-01-15',
                      'requested_by': 'app-team', 'evidence': ev},
        'exemption': {'finding': f, 'justification': 'the integration stays on this protocol by design',
                      'review_every_days': 90, 'requested_by': 'app-team', 'evidence': ev},
        'accepted-risk': {'finding': f, 'justification': 'legacy hardware awaiting migration funding',
                          'owner': 'ops-lead', 'review_date': '2027-02-01', 'risk_register_ref': 'RISK-42',
                          'requested_by': 'app-team', 'evidence': ev},
        'compliance-exception': {'finding': f, 'framework': 'PCI DSS 4.0', 'control_id': '4.2.1',
                                 'requirement_text': 'strong cryptography for transmission of cardholder data',
                                 'scope': {'from': 'legacy-pos', 'to': 'acct1', 'condition': 'until replacement'},
                                 'compensating_controls': ['private link only'], 'expires': '2027-01-31',
                                 'approving_authority': 'ciso', 'justification': 'the terminal fleet is replaced in Q1',
                                 'requested_by': 'app-team', 'evidence': ev},
        'mitigation': {'finding': f, 'justification': 'reachable only on a private endpoint',
                       'compensating_control': 'private endpoint only, public network access disabled',
                       'expires': '2027-01-31', 'requested_by': 'app-team', 'evidence': ev}}
    for name, item in good.items():
        check(tt.validate_item(name, item, 0, today=TODAY) is None, 'V7 a valid %s was refused: %r'
              % (name, tt.validate_item(name, item, 0, today=TODAY)))
    for label, name, item, code in (
            ('a false positive with no evidence', 'false-positive',
             dict((k, v) for k, v in good['false-positive'].items() if k != 'evidence'), tt.TEMPLATE_FIELD_INVALID),
            ('an exception past 90 days', 'exception', dict(good['exception'], expires='2027-06-01'),
             tt.EXCEPTION_TOO_LONG),
            ('an exception with no scope', 'exception', dict((k, v) for k, v in good['exception'].items()
                                                             if k != 'scope'), tt.TEMPLATE_FIELD_INVALID),
            ('an exception with no compensating control', 'exception',
             dict(good['exception'], compensating_controls=[]), tt.TEMPLATE_FIELD_INVALID),
            ('an exemption with no review cadence', 'exemption',
             dict((k, v) for k, v in good['exemption'].items() if k != 'review_every_days'), tt.TEMPLATE_FIELD_INVALID),
            ('an accepted risk with no risk register', 'accepted-risk',
             dict((k, v) for k, v in good['accepted-risk'].items() if k != 'risk_register_ref'), tt.TEMPLATE_FIELD_INVALID),
            ('a compliance exception with no authority', 'compliance-exception',
             dict((k, v) for k, v in good['compliance-exception'].items() if k != 'approving_authority'),
             tt.TEMPLATE_FIELD_INVALID)):
        r = tt.validate_item(name, item, 0, today=TODAY) or {}
        check(r.get('code') == code, 'V7 %s: %r, expected %s' % (label, r, code))
    want = {'false-positive': 'FALSE_POSITIVE_REQUEST', 'exception': 'EXCEPTION_REQUEST',
            'exemption': 'EXEMPTION_REQUEST', 'accepted-risk': 'ACCEPTED_RISK_REQUEST',
            'compliance-exception': 'COMPLIANCE_EXCEPTION_REQUEST', 'mitigation': 'MITIGATED_REQUEST'}
    v = V(pt, mods, tmp)
    for name, cls in sorted(want.items()):
        res = v.submit({'template': name, 'template_version': 2, 'items': [good[name]]})
        made = ((res.get('data') or {}).get('reconcile') or {}).get('created') or []
        check(made and made[0].get('ticket_class') == cls, 'V7 %s did not open a %s: %r %r'
              % (name, cls, made, codes(res)))
    check(rt.DISPOSITION_REQUESTS['exception'][1] == 'EXCEPTION_REQUEST',
          'V7 the reconciler still maps exception to %r' % (rt.DISPOSITION_REQUESTS['exception'],))
    # A false positive is re-checked when the tool version changes.
    fp = [i for i in v.t.issues.values() if 'secure-cicd-kit-tpl-false-positive' in i['fields']['labels']]
    res = v.submit(fparams(tt, F(tt, source_tool_version='5.0.0', evidence={'ref': 'x/2', 'sha256': '6' * 64})))
    check(fp and '%s-fp-recheck' % P in fp[0]['fields']['labels'] and
          any('RE-CHECK' in c and '5.0.0' in c for c in v.comments(fp[0]['id'])),
          'V7 a tool-version change did not re-check the false positive')


# ── V8 / V9 ────────────────────────────────────────────────────────────────────────────────

def v8(pt, mods, ti, sod, tmp):
    tt = mods[5]
    v = V(pt, mods, tmp)
    ref = _seed(v, tt)

    def ext(used, waiting='fix', **more):
        return v.submit({'template': 'extension', 'template_version': 2, 'items': [dict({
            'ref': ref, 'reason': 'the vendor moved the patch date by a month', 'extensions_used': used,
            'requested_by': 'app-team', 'evidence': {'ref': 'mail/1', 'sha256': 'c' * 64}, 'waiting_on': waiting},
            **more)]})
    res = ext(0)
    check(outcome(res) == tt.TEMPLATE_TICKET_UPDATED and any('2026-12-04' in c for c in v.comments(ref)),
          'V8 the default extension is not 30 days: %r' % items(res))
    ext(1)
    res = ext(2)
    check(codes(res) == ('API_TEMPLATE_RULE_REFUSED', tt.EXTENSION_LIMIT_REACHED),
          'V8 a third extension with a fix available was %r' % (codes(res),))
    v2_ = V(pt, mods, os.path.join(tmp, 'a'))
    ref = _seed(v2_, tt)
    v = v2_
    for used in (0, 1, 2, 3):
        res = ext(used, waiting='vendor')
        check(outcome(res) == tt.TEMPLATE_TICKET_UPDATED, 'V8 vendor extension %d was refused: %r'
              % (used + 1, codes(res)))
    adv = [c for c in v.comments(ref) if 'consider an alternative' in c]
    check(len(adv) == 1, 'V8 the vendor advisory was posted %d time(s), expected once at extension 2' % len(adv))


def v9(pt, mods, ti, sod, tmp):
    tt, rt, tb = mods[5], mods[2], mods[3]
    for sev, adv_day, escalated in (('medium', 180, False), ('high', 90, True), ('low', None, False)):
        v = V(pt, mods, os.path.join(tmp, sev))
        nf = F(tt, fix_status='NO_FIX_AVAILABLE', severity=sev)
        res = v.submit({'template': 'nofix-recheck', 'template_version': 2, 'items': [
            {'finding': nf, 'vendor': 'Contoso', 'requested_by': 'app-team', 'evidence': nf['evidence']}]})
        ref = (items(res) or [{}])[0].get('ref')
        if not check(ref, 'V9 %s: no no-fix ticket' % sev):
            continue
        import datetime
        d0 = datetime.date(2026, 11, 4)
        for days in (29, 30, 31, 60, 90, 91, 120, 150, 179, 180, 181):
            rt.resurface({}, rt.choose_backend(tb.JIRA_ENV)[0], True, (d0 + datetime.timedelta(days=days)).isoformat())
        cs = v.comments(ref)
        rechecks = [c for c in cs if 'RE-CHECK DUE' in c]
        reviews = [c for c in cs if 'NO-FIX REVIEW DUE' in c]
        advis = [c for c in cs if 'look for an alternative' in c]
        check(len(rechecks) == 6, 'V9 %s: %d re-check(s) by day 181, expected 6 (every 30 days)' % (sev, len(rechecks)))
        check(len(reviews) == 2, 'V9 %s: %d review(s) by day 181, expected 2 (every 90 days)' % (sev, len(reviews)))
        check(len(advis) == (1 if adv_day else 0), 'V9 %s: the advisory was posted %d time(s)' % (sev, len(advis)))
        bumped = any(r['json'] and 'priority' in json.dumps(r['json']) for r in v.x.replay.requests
                     if r['method'] == 'PUT')
        if escalated:
            check(bumped, 'V9 %s: the advisory did not escalate the priority' % sev)


# ── V10 / V11 ──────────────────────────────────────────────────────────────────────────────

PROPOSED = ('vendor-dependency', 'remediation-subtask', 'review-finding', 'pentest-finding', 'audit-finding',
            'cloud-misconfiguration', 'exposed-secret', 'licence', 'end-of-life', 'architecture-risk',
            'access-review-finding', 'incident-follow-up', 'policy-deviation', 'control-gap')


def v10(pt, mods, ti, sod, tmp):
    tt = mods[5]
    doc = io.open(os.path.join(ROOT, 'docs', 'ticketing', 'TICKET-TYPES.md'), encoding='utf-8').read()
    for name in PROPOSED:
        p = os.path.join(ROOT, 'api', 'v1', 'tickets', 'proposed', '%s.schema.json' % name)
        stub = json.load(io.open(p, encoding='utf-8')) if os.path.isfile(p) else {}
        check(stub.get('x-enabled') is False and name in doc, 'V10 %s is not listed, stubbed and disabled' % name)
        r = tt.validate_item(name, {}, 0) or {}
        check(r.get('code') == tt.TEMPLATE_NOT_ENABLED, 'V10 the proposed type %s was %r' % (name, r))


def v11(pt, mods, ti, sod, tmp):
    rt = mods[2]
    import prove_ticket_backends as tb
    # Azure DevOps: WIQL then workitemsbatch, paged by id.
    r = tb.install(tb.Replay())
    items_ = {}
    for i in range(1, 151):
        items_[1000 + i] = {'id': 1000 + i, 'fields': {'System.Title': 'item %d' % i, 'System.State': 'To Do',
                                                      'System.Tags': 'ops', 'System.Description': 'x'}}
    items_[1200] = {'id': 1200, 'fields': {'System.Title': 'TLS 1.0 on acct1', 'System.State': 'To Do',
                                           'System.Tags': 'secure-cicd-kit-ck-' + 'a' * 32,
                                           'System.Description': '<p>RULE-X on /subscriptions/s/acct1</p>'}}

    def wiql(rec):
        q = rec['json']['query']
        last = int(re.search(r'\[System\.Id\] > (\d+)', q).group(1))
        want = re.findall(r"CONTAINS '([^']+)'", q)
        ids = sorted(i for i, it in items_.items() if i > last and (not want or any(
            w.lower() in (' '.join(str(v) for v in it['fields'].values())).lower() for w in want)))
        return 200, {'workItems': [{'id': i} for i in ids[:50]]}, {}

    def batch(rec):
        return 200, {'value': [items_[i] for i in rec['json']['ids'] if i in items_]}, {}
    r.on('POST', r'/_apis/wit/wiql', wiql)
    r.on('POST', r'/_apis/wit/workitemsbatch', batch)
    b, note = rt.choose_backend(tb.AZDO_ENV)
    a = ti.adapter_for(b)
    got, state, _d = a.search_all(page_size=50)
    check(state == ti.TRACKER_INTAKE_COMPLETE and len(got) == 151, 'V11 Azure DevOps paging read %d (%s)'
          % (len(got), state))
    got, state, _d = a.search_all(text='RULE-X', ck_label='secure-cicd-kit-ck-' + 'a' * 32)
    check([t['ref'] for t in got] == ['1200'], 'V11 Azure DevOps exact/near search found %r' % [t['ref'] for t in got])
    # GitHub Issues: labels for exact, the search API for near, page numbers.
    r = tb.install(tb.Replay())
    issues = [{'number': n, 'title': 'issue %d' % n, 'state': 'open', 'labels': [{'name': 'ops'}], 'body': 'b'}
              for n in range(1, 131)]
    issues.append({'number': 200, 'title': 'TLS 1.0 on acct1', 'state': 'open',
                   'labels': [{'name': 'secure-cicd-kit-ck-' + 'a' * 32}], 'body': 'RULE-X on acct1'})

    def lst(rec):
        page = int(re.search(r'[?&]page=(\d+)', rec['url']).group(1))
        lab = re.search(r'labels=([^&]+)', rec['url'])
        hits = [i for i in issues if not lab or lab.group(1) in [x['name'] for x in i['labels']]]
        return 200, hits[(page - 1) * 50:page * 50], {}

    def srch(rec):
        q = re.search(r'q=([^&]+)', rec['url']).group(1)
        hits = [i for i in issues if 'RULE-X'.lower() in (i['title'] + i['body']).lower()] if 'RULE-X' in q else []
        return 200, {'total_count': len(hits), 'incomplete_results': False, 'items': hits}, {}
    r.on('GET', r'/repos/o/r/issues\?', lst)
    r.on('GET', r'/search/issues\?', srch)
    b, note = rt.choose_backend(tb.GH_ENV)
    a = ti.adapter_for(b)
    got, state, _d = a.search_all(page_size=50)
    check(state == ti.TRACKER_INTAKE_COMPLETE and len(got) == 131, 'V11 GitHub paging read %d (%s)' % (len(got), state))
    got, state, _d = a.search_all(text='RULE-X', ck_label='secure-cicd-kit-ck-' + 'a' * 32)
    check([t['ref'] for t in got] == ['200'], 'V11 GitHub exact/near search found %r' % [t['ref'] for t in got])
    # A duplicate record never carries the original's stamp, on any backend.
    rec = rt.RecordingBackend()
    ref, _d = rec.create({'cluster_key': 'k' * 32}, rt.render_body({'cluster_key': 'k' * 32, 'tier': 'singleton',
                                                                    'subject': '', 'severity': 'low', 'scanners': [],
                                                                    'members': [], 'member_identities': []}), 't')
    body = rt.duplicate_body('#%s' % ref, 'k' * 32, 'what it added')
    check(rt.STAMP_PREFIX not in body and ref in body, 'V11 a duplicate record carries a stamp line')
    # GitHub labels are at most 50 characters (found live, 2026-11-04: a 51-character correlation-key label
    # was a 422). The kit cuts them deterministically and the exact match compares both sides cut.
    ck = 'c' * 32
    long_label = 'secure-cicd-kit-ck-%s' % ck
    cut = rt.fit_label(long_label)
    # KDEC-043: the short form is a SEARCH AID. A hit is exact only when the body carries the full key; with no full
    # key it is a candidate for a person, never exact.
    m = ti.match({'correlation_key': ck, 'rule': 'R', 'aliases': [], 'asset_needle': '', 'title': ''},
                 [{'ref': '9', 'labels': [cut], 'summary': '', '_text': 'secure-cicd-kit-cluster: %s' % ck}],
                 long_label, 'secure-cicd-kit-cluster:', 85)
    check(len(long_label) > 50 and len(cut) == 50 and cut != long_label[:50] and len(m['exact']) == 1 and
          m['exact'][0][1].startswith('body-stamp'),
          'V11 a GitHub short correlation label with the full key in the body is not an exact match: %r' % m)
    m = ti.match({'correlation_key': ck, 'rule': 'R', 'aliases': [], 'asset_needle': '', 'title': ''},
                 [{'ref': '9', 'labels': [cut], 'summary': '', '_text': ''}], long_label, 'secure-cicd-kit-cluster:', 85)
    check(not m['exact'] and [x[1] for x in m['candidates']] == ['correlation-label-unverified'],
          'V11 a short label with no full key behind it was exact: %r' % m)
    gh = rt.GitHubIssues('o/r', 'placeholder-token', 'secure-cicd-kit', calibration='7')
    sent = []
    gh._req = lambda method, path, payload=None: (sent.append(payload) or ({'number': 5}, 201, None))
    gh.create({'cluster_key': ck, 'extra_labels': [long_label]}, 'body', 'title')
    gh.mark('5', labels=[long_label])
    check(sent and all(len(x) <= 50 for pl in sent if isinstance(pl, dict) for x in pl.get('labels') or []),
          'V11 a GitHub label longer than 50 characters was sent: %r' % sent)


def main():
    mods = imports()
    if mods is None:
        return 1
    pt, m, ti, sod = mods
    tmp = tempfile.mkdtemp(prefix='kit-intake-v2-')
    real = __import__('urllib.request').request.urlopen
    try:
        for case in (v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11):
            d = tempfile.mkdtemp(dir=tmp)
            try:
                case(pt, m, ti, sod, d)
            except (Exception, SystemExit) as exc:  # noqa: BLE001 -- a crash is a failed case, named
                import traceback
                FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                         traceback.format_exc()[-2500:]))
    finally:
        __import__('urllib.request').request.urlopen = real
        shutil.rmtree(tmp, ignore_errors=True)
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_ticket_intake_v2: V1..V11 hold -- separation of duties; the whole security list or team; a '
          'fixer\'s close is pending and only another person or a rescan closes; a feature-branch fix is observed, '
          'the mapped branch closes; exact is a closed duplicate, near is created for triage, pending and outbox '
          'lose nothing; trust beside confidence; the owner\'s taxonomy; extensions and the no-fix clock; '
          'proposed types disabled; search-first Azure DevOps and GitHub intake')
    return 0


if __name__ == '__main__':
    sys.exit(main())
