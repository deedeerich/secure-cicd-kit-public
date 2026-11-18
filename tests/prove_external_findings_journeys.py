#!/usr/bin/env python3
"""PROOF: an external finding that matches a kit finding ENHANCES its ticket, end to end (KDEC-049 R1-R5).

Owner ruling 2026-11-11: "It should never drop the vuln it should enhance the existing ticket with additional
evidence." Reviewer requirements (adopted by the coordinator): a SELECTED baseline AND the register; the identity
model; the structured record; duplicate closure only after a proven transfer; idempotent under retry,
concurrency and partial failure.

Each journey is a whole world (tests/prove_ticket_templates.py W: the kit API's run side, a stateful Jira):
existing kit finding + its canonical ticket -> the baseline selection (a fake REST API: runs, compare,
artifacts) -> the pull's identity model -> the review gate -> tickets.submit -> the ticket and the structured
record read back.

  J1  Sonar observation, baseline SELECTED: receipt, ENHANCED, no second ticket, structured record, read back
  J2  stale baseline (BASELINE_STALE) / J2b partial (BASELINE_PARTIAL) / J3 no baseline (BASELINE_UNAVAILABLE):
      never "no match" -- the register still matches, the items go to triage
  J4  same CVE, different component: MATCH_SEPARATE_INSTANCE, its own ticket, linked, never merged
  J5  mismatched scope: MATCH_SCOPE_MISMATCH        J6  ambiguous: MATCH_AMBIGUOUS, both kept
  J7  higher source severity, two levels: SEVERITY_MATERIAL_DISAGREEMENT, both assessments kept
  J8  active accepted risk on the match: DISPOSITION_REEVALUATION_REQUIRED, never extended or cleared
  J9  closed finding reappears: TEMPLATE_REGRESSION (the kit's reopen policy), evidence attached
  J10 failed tracker write (comment; then label) -> TEMPLATE_OUTBOX -> retry: one evidence comment
  J11 concurrent submission (the other writer lands between plan and write): EVIDENCE_ALREADY_ON_TICKET
  J12 missing canonical ticket: created in triage, evidence kept
  J13 duplicate closure whose transfer cannot be read back: TEMPLATE_DUPLICATE_CLOSURE_REFUSED, both open
  Mutants M-B1..M-B6 each break one guard and must be caught by the journey that reaches it.
"""
import copy
import datetime
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(os.path.dirname(HERE), 'scripts')]

import external_findings_baseline as EFB  # noqa: E402
import external_findings_pull as EFP  # noqa: E402

REPO, HEAD = 'example-org/app-one', 'a' * 40
CVE = 'CVE-2026-20001'


class FakeGH(object):
    """The documented REST shapes the selection reads. runs: [(id, sha, created_at, coverage_rows, ancestor)]."""

    def __init__(self, runs, observations):
        self.runs, self.obs = runs, observations

    def get(self, path):
        if path.startswith('/repos/%s/branches/' % REPO):
            return 200, {'commit': {'sha': HEAD}}, {}, None
        if '/actions/runs?' in path:
            rows = [{'id': r[0], 'head_sha': r[1], 'created_at': r[2], 'conclusion': 'success', 'head_branch': 'main',
                     'head_repository': {'full_name': REPO}} for r in self.runs]
            return 200, {'workflow_runs': rows, 'total_count': len(rows)}, {}, None
        if '/compare/' in path:
            sha = path.split('/compare/')[1].split('...')[0]
            anc = [r[4] for r in self.runs if r[1] == sha]
            return 200, {'status': 'ahead' if anc and anc[0] else 'diverged'}, {}, None
        if path.endswith('/artifacts?per_page=100'):
            rid = int(path.split('/actions/runs/')[1].split('/')[0])
            return 200, {'artifacts': [{'id': rid * 10, 'name': 'security-report-1', 'expired': False}],
                         'total_count': 1}, {}, None
        return 404, None, {}, 'not found'

    def download(self, path):
        rid = int(path.split('/actions/artifacts/')[1].split('/')[0]) // 10
        rows = [r[3] for r in self.runs if r[0] == rid][0]
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            z.writestr('findings.json', json.dumps(self.obs))
            z.writestr('findings-coverage.json', json.dumps({'schema': 'findings-coverage/1', 'rows': rows}))
        return b.getvalue()


def cov(scanner, established=True):
    return [{'scanner': scanner, 'applicability': 'APPLICABLE', 'established': established}]


def ago(days):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')


DEP = {'source_type': 'scan-app', 'source_tool': 'osv-scanner', 'environment': 'code',
       'asset': {'scheme': 'repo-path', 'repository': REPO, 'path': 'package-lock.json'},
       'identifier': CVE, 'severity': 'high', 'fix_status': 'FIX_AVAILABILITY_NOT_ESTABLISHED',
       'evidence': {'ref': 'kit-run/1/findings.json', 'sha256': 'b' * 64}, 'title': 'Unsafe deserialisation in pkgx'}
CODE = {'source_type': 'scan-app', 'source_tool': 'semgrep', 'environment': 'code',
        'asset': {'scheme': 'repo-path', 'repository': REPO, 'path': 'src/Db.java', 'line': 42},
        'identifier': 'java.sqli', 'cwe': 'CWE-89', 'severity': 'high', 'fix_status': 'FIX_AVAILABILITY_NOT_ESTABLISHED',
        'evidence': {'ref': 'kit-run/1/findings.json', 'sha256': 'c' * 64}, 'title': 'SQL injection in Db'}


def kit_obs(tt, base, **extra):
    """The kit finding as the security suite's findings.json carries it (same identity and stamp as its ticket)."""
    rec = tt.normalize('finding', base, {})
    o = {'identity': rec['identity'], 'where': rec['where'], 'finding_subject': rec['finding_subject'],
         'state': rec['identity_state'], 'what_aliases': list(rec['what_aliases']), 'scanner': base['source_tool'],
         'rule_id': base['identifier'], 'severity': base['severity'], 'canonical_path': base['asset']['path'],
         'line': base['asset'].get('line'), 'cwe': base.get('cwe', '')}
    o.update(extra)
    return o, rec['correlation_key']


def aik(n, sev='high', pkg='pkgx', repo='app-one'):
    return {'id': n, 'type': 'open_source', 'severity': sev, 'status': 'open', 'cve_id': CVE,
            'cwe_classes': ['CWE-502'], 'affected_package': pkg, 'affected_file': 'package-lock.json',
            'code_repo_name': repo}


def sonar_items():
    return [EFP._code_item('SonarQube Cloud', 'code', REPO, 'src/Db.java', 42, 'javasecurity:S3649', 'high', 'CWE-89',
                           'SQL injection', 'sonar:AX-1', {'key': 'AX-1'}, [], 'sonarcloud.io')]


class Run(object):
    def __init__(self, PT, mods, work, name):
        self.PT, self.mods, self.tt = PT, mods, mods[5]
        self.d = os.path.join(work, name)
        os.makedirs(self.d)
        self.w = PT.W(mods, self.d)
        self.out = []
        self.n = 0

    def claim(self, label, ok, detail=''):
        self.out.append((label, bool(ok), detail))
        return ok

    def ticket(self, base, rid='XJ-BASE-01'):
        res, _s = self.w.submit(self.w.finalize(rid, {'template': 'finding', 'template_version': 2, 'items': [base]}),
                                'xj-base-%s' % rid.lower())
        made = self.PT.items_of(res)
        return str(made[0]['ref']) if made and made[0].get('ref') else None

    def submit(self, pulled, rid):
        self.n += 1
        (params, _h), = EFP.batches(pulled, rid)
        res, _s = self.w.submit(self.w.finalize(rid, params), 'xj-%s-%04d' % (rid.lower(), self.n))
        return params, res, self.PT.items_of(res)

    def marks(self, ref):
        return [c for c in self.w.t.comments if str(c[0]) == ref and 'kit-observation sha256:' in c[1]]

    def labels(self, ref):
        return set(self.w.t.issues[ref]['fields'].get('labels') or [])

    def saved(self, name):
        """The NEWEST such file the kit API's run side saved in this world (each call has its own out dir)."""
        found = []
        for root, _ds, fs in os.walk(self.d):
            if name in fs:
                found.append(os.path.join(root, name))
        if not found:
            return None
        return json.load(io.open(max(found, key=os.path.getmtime), encoding='utf-8'))


def select(runs, obs):
    return EFB.select(FakeGH(runs, obs), REPO, 'main', 'SOURCE_DEPENDENCY' if obs and obs[0]['scanner'] == 'osv-scanner'
                      else 'SOURCE')


def journeys(PT, mods, work, tag, only=None):
    import ticket_submit as TS
    out = []
    want = lambda j: only is None or j in only or any(o.startswith(j) and o[len(j):].isalpha() for o in only)  # noqa: E731

    if want('J1'):
        r = Run(PT, mods, work, tag + 'j1')
        ref = r.ticket(CODE)
        o, ck = kit_obs(r.tt, CODE)
        receipt, bobs = select([(901, 'd' * 40, ago(1), cov('semgrep'), True)], [o])
        r.claim('J1 the baseline is %s with its receipt (repository, run id, commit, timestamp, artifact digest, '
                'completeness)' % EFB.SELECTED, receipt['state'] == EFB.SELECTED and receipt['run_id'] == 901 and
                receipt['commit_sha'] == 'd' * 40 and receipt['artifact_digest'].startswith('sha256:') and
                receipt.get('created_at') and 'ESTABLISHED' in receipt.get('completeness', ''), receipt)
        pulled = EFP.finish('sonarqube', sonar_items(), [], [], bobs, {}, receipt)
        it = pulled['items'][0]
        r.claim('J1 the Sonar observation %s the kit finding %s (register baseline-run)' % (EFP.ENHANCES, ck[:12]),
                (it.get('enhances') or {}).get('correlation_key') == ck and it['enhances'].get('register') == 'baseline-run'
                and pulled['baseline']['run_id'] == 901, it.get('enhances'))
        n0 = len(r.w.t.issues)
        (params, _h), = EFP.batches(pulled, 'XJ-1')
        res, _s = r.w.submit(params, 'xj-1-norev')
        r.claim('J1 the review gate refuses an unreviewed enhancement: API_REVIEW_NOT_FINALIZED, nothing written',
                (res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED' and not r.marks(ref), res.get('refusal'))
        _p, res, items = r.submit(pulled, 'XJ-1')
        fp = (items[0] if items else {}).get('fingerprint') or ''
        r.claim('J1 %s on the canonical ticket, no second ticket' % r.tt.TEMPLATE_ENHANCED_EXISTING,
                items and items[0].get('outcome') == r.tt.TEMPLATE_ENHANCED_EXISTING and str(items[0].get('ref')) == ref
                and len(r.w.t.issues) == n0, items)
        led = r.saved('ticket-ledger-proposal.json') or {}
        obs = ((led.get('clusters') or {}).get(ck) or {}).get('evidence_observations') or []
        r.claim('J1 the structured record holds the observation (fingerprint, source tool/key, scope, severity as rated, '
                'aliases, evidence ref, canonical identity) under %s' % ck[:12],
                len(obs) == 1 and obs[0]['fingerprint'] == fp and obs[0]['source_key'] == 'sonar:AX-1' and
                obs[0]['severity_as_rated'] == 'high' and obs[0]['scope']['asset'] and obs[0]['evidence_ref'] and
                obs[0]['canonical_finding']['cluster_key'] == ck, obs)
        r.claim('J1 reconciliation reads back all evidence: the comment carries the fingerprint marker once',
                len(r.marks(ref)) == 1 and fp in r.marks(ref)[0][1], len(r.marks(ref)))
        out += r.out

    if want('J2'):
        r = Run(PT, mods, work, tag + 'j2')
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP)
        receipt, bobs = select([(902, 'd' * 40, ago(30), cov('osv-scanner'), True)], [o])
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(1)], {'app-one': REPO}, 'code')[0], [], [], bobs, {}, receipt)
        _p, _res, items = r.submit(pulled, 'XJ-2')
        r.claim('J2 a stale baseline is %s: the match is kept and the item goes to triage (baseline-review)'
                % EFB.STALE, receipt['state'] == EFB.STALE and items and items[0].get('baseline_state') == EFB.STALE and
                {'secure-cicd-kit-baseline-review', 'secure-cicd-kit-triage'} <= r.labels(ref), (receipt['state'], items))
        receipt2, bobs2 = select([(903, 'd' * 40, ago(1), cov('osv-scanner', established=False), True)], [o])
        p2 = EFP.finish('aikido', EFP.aikido_items([aik(2)], {'app-one': REPO}, 'code')[0], [], [], bobs2, {}, receipt2)
        r.claim('J2b a partial scanner population is %s: no baseline observation is used, every item carries the state'
                % EFB.PARTIAL, receipt2['state'] == EFB.PARTIAL and not bobs2 and
                p2['items'][0]['baseline']['state'] == EFB.PARTIAL, receipt2)
        receipt3, _b3 = select([(904, 'e' * 40, ago(1), cov('osv-scanner'), False)], [o])
        r.claim('J2c a run whose commit is not an ancestor of the default-branch head is never selected (%s)'
                % EFB.UNAVAILABLE, receipt3['state'] == EFB.UNAVAILABLE and 'ancestor' in json.dumps(receipt3), receipt3)
        out += r.out

    if want('J3'):
        r = Run(PT, mods, work, tag + 'j3')
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP)
        receipt, bobs = select([], [o])
        reg = {ck: {'ref': ref, 'key': 'KIT-%s' % ref, 'members': [dict(o, uri=o['canonical_path'])]}}
        regobs = EFB.register_observations(reg, REPO)
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(3)], {'app-one': REPO}, 'code')[0], [], [], bobs + regobs, {},
                            receipt)
        it = pulled['items'][0]
        r.claim('J3 no baseline (%s) is never "no match": the register (ticket ledger) still matches %s'
                % (EFB.UNAVAILABLE, ck[:12]), receipt['state'] == EFB.UNAVAILABLE and
                (it.get('enhances') or {}).get('register') == 'ticket-ledger' and it['baseline']['state'] == EFB.UNAVAILABLE,
                (receipt['state'], it.get('enhances')))
        n0 = len(r.w.t.issues)
        _p, _res, items = r.submit(pulled, 'XJ-3')
        r.claim('J3 the register match enhances the ticket in triage, no second ticket',
                items and items[0].get('outcome') == r.tt.TEMPLATE_ENHANCED_EXISTING and len(r.w.t.issues) == n0 and
                'secure-cicd-kit-triage' in r.labels(ref), items)
        out += r.out

    for j, label, kit_extra, rows, state in (
            ('J4', 'same CVE on a different component', {'component': 'pkgx'}, [aik(4, pkg='pkgy')], EFB.SEPARATE),
            ('J5', 'the same CVE and path in another repository', {}, [aik(5, repo='app-two')], EFB.MATCH_SCOPE_MISMATCH),
            ('J6', 'two kit clusters qualify', {}, [aik(6)], EFB.AMBIGUOUS)):
        if not want(j):
            continue
        r = Run(PT, mods, work, tag + j.lower())
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP, **kit_extra)
        o['repository'] = REPO
        kit = [dict(o, cluster_key=ck, register='baseline-run')]
        if j == 'J6':
            kit.append(dict(o, cluster_key='9' * 32, register='ticket-ledger'))
        pulled = EFP.finish('aikido', EFP.aikido_items(rows, {'app-one': REPO, 'app-two': 'example-org/app-two'},
                                                       'code')[0], [], [], kit, {}, {'state': EFB.SELECTED})
        it = pulled['items'][0]
        n0, m0 = len(r.w.t.issues), len([c for c in r.w.t.comments if str(c[0]) == ref])
        _p, _res, items = r.submit(pulled, 'XJ-%s' % j[1:])
        new = [i for i in r.w.t.issues if i not in (ref,)]
        r.claim('%s %s is %s: its own ticket, related named, never merged into %s' % (j, label, state, ck[:12]),
                'enhances' not in it and (it.get('match_review') or {}).get('state') == state and
                ck in it['match_review']['candidates'] and len(r.w.t.issues) == n0 + 1 and
                len([c for c in r.w.t.comments if str(c[0]) == ref]) == m0 and
                any(state in c[1] for c in r.w.t.comments if str(c[0]) in new) and
                'secure-cicd-kit-match-review' in set(r.w.t.issues[new[-1]]['fields'].get('labels') or []),
                (it.get('match_review'), items))
        out += r.out

    if want('J7'):
        r = Run(PT, mods, work, tag + 'j7')
        base = dict(DEP, severity='low')
        ref = r.ticket(base)
        o, ck = kit_obs(r.tt, base)
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(7, sev='critical')], {'app-one': REPO}, 'code')[0], [], [],
                            [dict(o, cluster_key=ck, repository=REPO)], {}, {'state': EFB.SELECTED})
        _p, _res, items = r.submit(pulled, 'XJ-7')
        txt = r.marks(ref)[0][1] if r.marks(ref) else ''
        r.claim('J7 a source two levels higher is %s: both assessments kept, flagged, the ticket not re-prioritised'
                % TS.SEVERITY_MATERIAL_DISAGREEMENT, items and items[0].get('severity_disagreement') == TS.SEVERITY_MATERIAL_DISAGREEMENT and
                'secure-cicd-kit-severity-disagreement' in r.labels(ref) and 'secure-cicd-kit-sev-low' in r.labels(ref)
                and 'critical' in txt and TS.SEVERITY_MATERIAL_DISAGREEMENT in txt, items)
        out += r.out

    if want('J8'):
        r = Run(PT, mods, work, tag + 'j8')
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP)
        disp = {'disposition_type': 'ACCEPTED_RISK', 'state': 'approved', 'expires': '2027-01-31'}
        reg = {ck: {'ref': ref, 'members': [dict(o, uri=o['canonical_path'], disposition=disp)]}}
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(8)], {'app-one': REPO}, 'code')[0], [], [],
                            EFB.register_observations(reg, REPO), {}, {'state': EFB.SELECTED})
        l0 = r.labels(ref)
        _p, _res, items = r.submit(pulled, 'XJ-8')
        txt = r.marks(ref)[0][1] if r.marks(ref) else ''
        r.claim('J8 an active accepted risk on the match is %s: evidence attached, disposition marked for re-evaluation '
                '(scope, validity, expiry), nothing extended or cleared' % TS.DISPOSITION_REEVALUATION_REQUIRED,
                items and items[0].get('disposition_review') == TS.DISPOSITION_REEVALUATION_REQUIRED and l0 <= r.labels(ref) and
                'secure-cicd-kit-disposition-reevaluate' in r.labels(ref) and '2027-01-31' in txt and
                'ACCEPTED_RISK' in txt, items)
        out += r.out

    if want('J9'):
        r = Run(PT, mods, work, tag + 'j9')
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP)
        r.w.t.issues[ref]['fields']['status'] = {'name': 'Done', 'statusCategory': {'key': 'done'}}
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(9)], {'app-one': REPO}, 'code')[0], [], [],
                            [dict(o, cluster_key=ck, repository=REPO, ticket_state='closed')], {}, {'state': EFB.SELECTED})
        _p, _res, items = r.submit(pulled, 'XJ-9')
        r.claim('J9 a closed finding reappearing is %s under the kit\'s reopen policy, the evidence attached'
                % r.tt.TEMPLATE_REGRESSION, items and items[0].get('outcome') == r.tt.TEMPLATE_REGRESSION and
                (r.w.t.status_of(ref).get('statusCategory') or {}).get('key') != 'done' and len(r.marks(ref)) == 1 and
                any('REGRESSION' in c[1] for c in r.w.t.comments if str(c[0]) == ref), items)
        out += r.out

    if want('J10'):
        for part, route, method in (('comment', r'/rest/api/3/issue/\d+/comment$', 'POST'),
                                    ('label', r'/rest/api/3/issue/\d+$', 'PUT')):
            r = Run(PT, mods, work, tag + 'j10' + part)
            ref = r.ticket(DEP)
            o, ck = kit_obs(r.tt, DEP)
            pulled = EFP.finish('aikido', EFP.aikido_items([aik(10)], {'app-one': REPO}, 'code')[0], [], [],
                                [dict(o, cluster_key=ck, repository=REPO)], {}, {'state': EFB.SELECTED})
            real = [h for m, rx, h in r.w.replay.routes if m == method and rx.pattern == route][0]
            r.w.replay.on(method, route, lambda rec: (500, {'errorMessages': ['down']}, {}))
            _p, _res, items = r.submit(pulled, 'XJ-10')
            held = r.saved('outbox.json') or {}
            first = items and items[0].get('outcome') == r.tt.TEMPLATE_OUTBOX and held.get('items') == [0]
            r.w.replay.on(method, route, real)
            _p, _res, items = r.submit(pulled, 'XJ-10')
            r.claim('J10 a failed %s write goes to the outbox (%s, nothing lost); the retry leaves ONE evidence comment '
                    '(%s) and the labels' % (part, r.tt.TEMPLATE_OUTBOX, TS.EVIDENCE_ALREADY_ON_TICKET),
                    first and items and items[0].get('outcome') == r.tt.TEMPLATE_ENHANCED_EXISTING and
                    len(r.marks(ref)) == 1 and 'secure-cicd-kit-enhanced' in r.labels(ref), (first, items, len(r.marks(ref))))
            out += r.out

    if want('J11'):
        r = Run(PT, mods, work, tag + 'j11')
        ref = r.ticket(DEP)
        o, ck = kit_obs(r.tt, DEP)
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(11)], {'app-one': REPO}, 'code')[0], [], [],
                            [dict(o, cluster_key=ck, repository=REPO)], {}, {'state': EFB.SELECTED})
        fp = TS.fingerprint(r.tt.normalize('finding', pulled['items'][0], {}))
        route = r'/rest/api/3/issue/\d+/comment\?'
        real = [h for m, rx, h in r.w.replay.routes if m == 'GET' and rx.pattern == route][0]
        state = {'done': False}

        def other_writer_lands(rec):
            # THE OTHER WORKER: it planned too, and its comment landed between this one's plan and its write.
            if not state['done']:
                state['done'] = True
                r.w.t.comments.append((ref, 'ADDITIONAL EVIDENCE (the other worker)\n- kit-observation sha256:%s' % fp))
            return real(rec)
        r.w.replay.on('GET', route, other_writer_lands)
        _p, _res, items = r.submit(pulled, 'XJ-11')
        r.claim('J11 two concurrent submissions leave ONE evidence comment (%s)' % TS.EVIDENCE_ALREADY_ON_TICKET,
                items and items[0].get('outcome') == r.tt.TEMPLATE_ENHANCED_EXISTING and len(r.marks(ref)) == 1,
                (items, len(r.marks(ref))))
        out += r.out

    if want('J12'):
        r = Run(PT, mods, work, tag + 'j12')
        r.ticket(DEP)
        o, _ck = kit_obs(r.tt, DEP)
        pulled = EFP.finish('aikido', EFP.aikido_items([aik(12)], {'app-one': REPO}, 'code')[0], [], [],
                            [dict(o, cluster_key='f' * 32, repository=REPO)], {}, {'state': EFB.SELECTED})
        n0 = len(r.w.t.issues)
        _p, _res, items = r.submit(pulled, 'XJ-12')
        new = [i for i in r.w.t.issues.values()][-1]
        r.claim('J12 a missing canonical ticket: created in triage (%s), the evidence kept'
                % r.tt.TEMPLATE_POSSIBLE_DUPLICATE, items and items[0].get('outcome') == r.tt.TEMPLATE_POSSIBLE_DUPLICATE
                and len(r.w.t.issues) == n0 + 1 and 'secure-cicd-kit-triage' in (new['fields'].get('labels') or []), items)
        out += r.out

    if want('J13'):
        for broken in (False, True):
            r = Run(PT, mods, work, tag + 'j13' + ('b' if broken else 'a'))
            ref = r.ticket(DEP)
            if broken:
                r.w.replay.on('GET', r'/rest/api/3/issue/\d+/comment\?', lambda rec: (500, {'errorMessages': ['x']}, {}))
            again = dict(DEP, source_tool='trivy', evidence={'ref': 'kit-run/2/findings.json', 'sha256': 'e' * 64})
            res, _s = r.w.submit(r.w.finalize('XJ-13', {'template': 'finding', 'template_version': 2, 'items': [again]}),
                                 'xj-13-%s' % broken)
            items = r.PT.items_of(res)
            dref = str((items[0] if items else {}).get('duplicate_ref') or '')
            dstate = (r.w.t.status_of(dref).get('statusCategory') or {}).get('key') if dref else None
            if broken:
                r.claim('J13 a duplicate whose evidence transfer cannot be read back is %s: both stay open, linked'
                        % r.tt.TEMPLATE_DUPLICATE_CLOSURE_REFUSED,
                        items and items[0].get('outcome') == r.tt.TEMPLATE_DUPLICATE_CLOSURE_REFUSED and dref and
                        dstate != 'done' and any(r.tt.TEMPLATE_DUPLICATE_CLOSURE_REFUSED in c[1] for c in r.w.t.comments
                                                 if str(c[0]) == dref), (items, dstate))
            else:
                r.claim('J13 positive: a proven transfer closes the duplicate (%s)' % r.tt.TEMPLATE_CLOSED_DUPLICATE,
                        items and items[0].get('outcome') == r.tt.TEMPLATE_CLOSED_DUPLICATE and dstate == 'done',
                        (items, dstate))
            out += r.out
    return out


def mutate(mod, name, fn):
    real = getattr(mod, name)
    setattr(mod, name, fn)
    return lambda: setattr(mod, name, real)


def main():
    import prove_ticket_templates as PT
    import ticket_submit as TS
    mods = PT.imports()
    if mods is None:
        print('FAIL: the ticket machinery does not import')
        return 1
    work = tempfile.mkdtemp(prefix='kit-xf-journeys-')
    results = []
    try:
        results = journeys(PT, mods, work, 'p-')
        mutants = (
            ('M-B1 "the scanner population need not be COMPLETE"', 'J2b', EFB, 'capability_complete',
             lambda cov_, cap: ('COMPLETE', 'mutant'), EFB.PARTIAL),
            ('M-B2 "a CVE alone is the same vulnerability (component ignored)"', 'J4', EFB, '_path_eq',
             lambda a, b: True, EFB.SEPARATE),
            ('M-B3 "the read-back before the evidence comment is ignored"', 'J11', TS, '_comment_texts',
             _reads_but_ignores(TS._comment_texts), TS.EVIDENCE_ALREADY_ON_TICKET),
            ('M-B4 "close the duplicate without proving the transfer"', 'J13', TS, 'transfer_verified',
             lambda *a: (True, ''), mods[5].TEMPLATE_DUPLICATE_CLOSURE_REFUSED),
            ('M-B5 "the register is not read"', 'J3', EFB, 'register_observations', lambda led, repo: [], EFB.UNAVAILABLE))
        for label, j, mod, name, fn, guard in mutants:
            if name == '_path_eq':
                # component-blind AND path-blind for the separate-instance check: the CVE alone decides
                restore = mutate(mod, 'classify', _cve_only_classify(EFB))
            else:
                restore = mutate(mod, name, fn)
            try:
                got = journeys(PT, mods, work, 'm%d-' % len(results), only={j})
            finally:
                restore()
            failed = [lb for lb, ok, _d in got if not ok]
            results.append(('%s is caught by %s, naming %s' % (label, j, guard),
                            any(lb.startswith(j) and guard in lb for lb in failed), failed))
        # M-B6 "the evidence label is written before the comment succeeds": a SOURCE mutant of _write that marks
        # the ticket ahead of the guard. Caught by J10 (comment part) AT THE GUARD: the retry reads the label as
        # "already there" and binds (TEMPLATE_TICKET_BOUND) with no evidence comment -- the evidence is lost.
        restore = mutate(TS, '_write', _label_before_comment_write(TS))
        try:
            got = journeys(PT, mods, work, 'm%d-' % len(results), only={'J10'})
        finally:
            restore()
        hit = [(lb, d) for lb, ok, d in got if not ok and lb.startswith('J10 a failed comment write')]
        lost = bool(hit) and isinstance(hit[0][1], tuple) and hit[0][1][2] == 0 and any(
            (i or {}).get('outcome') == mods[5].TEMPLATE_TICKET_BOUND for i in hit[0][1][1] or [])
        results.append(('M-B6 "the evidence label is written before the comment succeeds" is caught by J10 at its '
                        'guard: the retry binds (%s) with no evidence comment' % mods[5].TEMPLATE_TICKET_BOUND,
                        lost, [(lb, ok) for lb, ok, _d in got]))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    bad = 0
    for label, ok, detail in results:
        print('  %s %s%s' % ('ok  ' if ok else 'FAIL', label, '' if ok else '\n       %s' % (json.dumps(detail, default=str)[:600])))
        bad += 0 if ok else 1
    if bad:
        print('FAIL: %d claim(s) did not hold' % bad)
        return 1
    print('PASS: every journey enhances, separates, routes or refuses by name; every mutant is caught at its guard.')
    return 0


def _reads_but_ignores(real):
    def comment_texts(backend, ref):
        real(backend, ref)
        return [], True
    return comment_texts


def _label_before_comment_write(TS):
    """ticket_submit._write with the evidence labels written BEFORE the comment's success is checked."""
    import inspect
    src = inspect.getsource(TS._write)
    anchor = '            if not r1[0]:\n                # THE EVIDENCE LABEL NEVER PRECEDES THE EVIDENCE'
    if src.count(anchor) != 1:
        raise AssertionError('M-B6: the guard this mutant moves is not in ticket_submit._write')
    src = src.replace(anchor, "            backend.mark(t['ref'], labels=sorted(set(labs)))  # MUTANT M-B6\n" + anchor)
    ns = {}
    exec(compile(src, TS.__file__ + ' (mutant M-B6)', 'exec'), TS.__dict__, ns)
    return ns['_write']


def _cve_only_classify(EFB):
    def classify(item, kit, repo=None):
        cves = {a.upper() for a in item.get('aliases', []) if str(a).upper().startswith('CVE-')}
        for o in kit:
            if cves & {str(a).upper() for a in o.get('what_aliases') or []}:
                return EFB.MATCHED, o, 'kit-finding-cve-path', []
        return EFB.NO_MATCH, None, '', []
    return classify


if __name__ == '__main__':
    sys.exit(main())
