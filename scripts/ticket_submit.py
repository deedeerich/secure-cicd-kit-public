#!/usr/bin/env python3
"""tickets.submit, carried out: the review gate, separation of duties, dedupe against every ticket, the
writes, and nothing ever lost. (KDEC-037; the owner's rulings of 2026-11-04.)

    scripts/kit_api_server.py calls submit() from the API's tickets phase; the scheduled clock
    (scripts/reconcile_tickets.py resurface) calls dedupe_pending_pass().

THE ORDER, AND WHY

    1  every item is validated against its template           (API_TEMPLATE_INVALID, nothing read)
    2  the review: finalized, bound to this evidence set, concurred by an approver who authored none of
       it (API_REVIEW_NOT_FINALIZED); a DISAGREE sends items back with the dissent recorded
    3  the item-level separation of duties (SOD_SELF_APPROVAL)
    4  READS: the kit's stamp sweep and every ticket in the tracker (scripts/ticket_intake.py); a rule that
       needs the tracker's state refuses BEFORE the first write (API_TEMPLATE_RULE_REFUSED)
    5  WRITES, each item ending in one of ticket_templates.TERMINAL_OUTCOMES:
         exact           -> a CLOSED DUPLICATE under the original, which is told what it added; the same
                            contribution again adds nothing (BOUND); a closed original newly observed is a
                            REGRESSION
         near            -> CREATED, flagged possible-duplicate, in triage; a person decides (template triage)
         not searched    -> CREATED in triage as DEDUPE PENDING; the next run re-runs its dedupe
         unreachable     -> the OUTBOX: a durable record kept as an artifact, alerted, drained by a later run
         none            -> CREATED through the reconciler (stamped, routed, recorded)
"""
import datetime
import io
import json
import os

import finding_correlation as fc
import review_finalize as rf
import separation_of_duties as sod
import ticket_intake as ti
import ticket_governance as tg
import ticket_model as tm
import ticket_templates as tt

ANSWER_COMPLETED, ANSWER_FAILED, ANSWER_REFUSED = 'API_COMPLETED', 'API_FAILED', 'API_REFUSED'


def _lab(stamp, word):
    return '%s-%s' % (stamp or 'secure-cicd-kit', word)


def _needle(akey):
    """The text a manual ticket would carry for an asset, from its key (for the pending re-check)."""
    parts = str(akey or '').split(':')
    if parts and parts[0] in ('azure', 'aws') and len(parts) >= 4:
        return ':'.join(parts[3:]).lower()
    if parts and parts[0] == 'repo' and len(parts) >= 3:
        return ':'.join(parts[2:]).lower()
    if parts and parts[0] == 'engagement' and len(parts) >= 3:
        return parts[2].lower()
    return str(akey or '').split('/', 1)[-1].lower()


def _row(text, name):
    for line in str(text or '').split('\n'):
        s = line.strip()
        if s.startswith('| %s |' % name):
            parts = s.split('|')
            return parts[2].strip() if len(parts) > 3 else ''
    return ''


def confidence_for(tools, anchor, evidence=True):
    """-> (score, basis): the corroboration score of a finding seen by `tools` (finding_correlation)."""
    tools = sorted(set(t for t in tools if t)) or ['unknown']
    obs = [{'job': 'external', 'source_type': 'external', 'tool': t, 'scanner': t, 'identity': 'x',
            'provenance': {'evidence_sha256': 'e' if evidence else ''}} for t in tools]
    cl = {'tier': fc.ANCHORED if len(obs) > 1 else fc.SINGLETON, 'identity_established': True,
          'members': list(range(len(obs))), 'anchor': anchor}
    return fc.corroboration_score(cl, obs)


# ═════════════════════════════════════════════════════════════════════════════════════
# THE PENDING DEDUPE, RE-RUN (the next submission, and the clock)
# ═════════════════════════════════════════════════════════════════════════════════════

def dedupe_pending_pass(result, backend, sweep_map, today, apply_changes):
    """Every kit ticket still labelled dedupe-pending gets its dedupe re-run: an exact other ticket closes it
    as a duplicate of that one; a near one flags it for triage; nothing found ends the pending state. A search
    that still cannot complete leaves it pending -- never lost."""
    stamp = getattr(backend, 'stamp_label', '') or 'secure-cicd-kit'
    adapter = ti.adapter_for(backend)
    if not hasattr(adapter, 'search_all'):
        return
    done = result.setdefault('dedupe_rechecked', [])
    for key in sorted(sweep_map or {}):
        for hit in sweep_map[key]:
            labels = set(hit.get('labels') or [])
            if not _has(labels, _lab(stamp, 'dedupe-pending')) or _has(labels, _lab(stamp, 'dedupe-done')) or \
                    not hit.get('ref'):
                continue
            desc, ok, _d = backend.read_description(hit['ref'])
            text = backend.description_text(desc) if ok else ''
            ident = _row(text, 'identifier')
            akey = _row(text, 'asset').rsplit('(`', 1)[-1].rstrip('`)') if '(`' in _row(text, 'asset') else ''
            tickets, state, sdetail = adapter.search_all(text=ident or None, ck_label=_lab(stamp, 'ck-%s' % key))
            if state != ti.TRACKER_INTAKE_COMPLETE:
                done.append({'ref': hit['ref'], 'state': state, 'detail': sdetail})
                continue
            # Every other ticket: ticket_intake.match itself sets aside one whose full key is another finding's, and
            # sends a label hit it cannot verify to a person (KDEC-043).
            pool = [t for t in tickets if str(t['ref']) != str(hit['ref'])]
            m = ti.match({'correlation_key': key, 'rule': ident, 'aliases': [], 'asset_needle': _needle(akey),
                          'title': ''}, pool, _lab(stamp, 'ck-%s' % key), 'secure-cicd-kit-cluster:', 101)
            rec = {'ref': hit['ref'], 'cluster_key': key, 'state': state}
            if not apply_changes:
                rec['planned'] = True
            elif m['exact']:
                other = m['exact'][0][0]
                backend.comment(hit['ref'], 'Dedupe re-run (secure-cicd-kit, %s): this ticket is a DUPLICATE of %s '
                                '(%s); closed as a duplicate.' % (today, other.get('key') or other['ref'], m['exact'][0][1]))
                backend.mark(hit['ref'], labels=[_lab(stamp, 'dedupe-done'), _lab(stamp, 'duplicate')])
                backend.close(hit['ref'])
                backend.comment(other['ref'], 'Dedupe re-run (secure-cicd-kit, %s): ticket %s was a duplicate of this one '
                                'and is closed.' % (today, hit.get('key') or hit['ref']))
                rec['outcome'] = tt.TEMPLATE_CLOSED_DUPLICATE
            elif m['candidates']:
                backend.comment(hit['ref'], 'Dedupe re-run (secure-cicd-kit, %s): possible duplicate of %s -- a person '
                                'decides merge or separate.' % (today, ', '.join(t.get('key') or t['ref']
                                                                                for t, _b, _s in m['candidates'])))
                backend.mark(hit['ref'], labels=[_lab(stamp, 'dedupe-done'), _lab(stamp, 'possible-duplicate'),
                                                 _lab(stamp, 'triage')])
                rec['outcome'] = tt.TEMPLATE_POSSIBLE_DUPLICATE
            else:
                backend.comment(hit['ref'], 'Dedupe re-run (secure-cicd-kit, %s): the search completed and found no other '
                                'ticket for this finding.' % today)
                backend.mark(hit['ref'], labels=[_lab(stamp, 'dedupe-done')])
                rec['outcome'] = tt.TEMPLATE_TICKET_CREATED
            done.append(rec)


# ═════════════════════════════════════════════════════════════════════════════════════
# SUBMIT
# ═════════════════════════════════════════════════════════════════════════════════════

class Plan(object):
    """Everything decided before the first write."""

    def __init__(self):
        self.items = []          # per-item answer dicts
        self.actions = []        # (kind, payload) writes, in order
        self.to_reconcile = []   # records the reconciler creates
        self.post = []           # after reconcile: (kind, ck, payload)


def _refused(code, r, data):
    return ANSWER_REFUSED, dict(data, template_refusal=r), [], '', {'code': code, 'detail': '%s: %s' % (
        r['code'], r['detail'])}


def submit(ctx, p, dry):
    """-> (api_state, data, notes, routing_result, refusal or None). `ctx` (scripts/kit_api_server.py):
    rt, backend, ledger, routing, central, repo_reg, client, repo, default_branch, actor, correlation_id,
    evidence (fn run_id, any_branch -> run, recs, cov, refusal), out_dir, today, run_url, commit, settings,
    approver_source, reviews_dir, branch_map, approved_tools, evidence_stores."""
    rt, backend, ledger = ctx['rt'], ctx['backend'], ctx['ledger']
    settings, today = ctx['settings'], ctx['today']
    r = tt.validate_submit(p, settings, today)
    data = {'backend': getattr(backend, 'name', None), 'dry_run': dry, 'template': p.get('template'),
            'template_version': p.get('template_version'), 'items': [], 'review': None, 'notifications': [],
            'alerts': [], 'dissent': []}
    if r:
        return _refused('API_TEMPLATE_INVALID', r, data)
    template = p['template']
    ev_sha = tt.evidence_set_sha256(p)
    data['evidence_set_sha256'] = ev_sha
    actor = ctx.get('actor') or {}
    callers = [actor.get('actor'), actor.get('triggering_actor'), actor.get('on_behalf_of')]
    approver, approval, gate = '', None, None
    if tt.needs_review(p):
        approvers, anote = rf.load_approvers_source(ctx.get('approver_source') or tt.DEFAULT_APPROVER_SOURCE,
                                                   ctx.get('central') or '', ctx.get('reviews_dir') or '',
                                                   ctx.get('team_client') or ctx.get('client'))
        gate = rf.check(p.get('review_id'), ev_sha, ctx.get('reviews_dir') or '', approvers, anote,
                        [c for c in callers if c], today, settings['review_max_age_days'], ctx.get('client'),
                        ctx['repo'], ctx['default_branch'], tt.load_template('review-record'))
        data['review'] = {k: gate.get(k) for k in ('state', 'review_id', 'concurred_by', 'reasons', 'facts',
                                                   'approvers_source', 'decision', 'roles')}
        if gate['state'] != rf.REVIEW_FINALIZED:
            return ANSWER_REFUSED, data, [], '', {'code': 'API_REVIEW_NOT_FINALIZED', 'detail': '%s: %s' % (
                rf.REVIEW_NOT_FINALIZED, '; '.join(gate['reasons']))}
        approver = gate['concurred_by']
        approval = tm.Approval(actor='review-concurrence', reason='review %s finalized and concurred by %s on %s '
                               '(evidence set %s)' % (p.get('review_id'), approver,
                                                      (gate.get('record') or {}).get('concurred_on'), ev_sha[:16]))
    else:
        data['review'] = {'state': 'not required', 'reasons': ['a fixer\'s own resolve (pending, never final) or a '
                                                               'verification by the kit\'s own rescan']}
    # ── the dissent: a DISAGREE sends items back, recorded ───────────────────────────────────────
    sent_back = set()
    if gate:
        rec = gate.get('record') or {}
        for i in range(len(p['items'])):
            d = (gate.get('item_decisions') or {}).get(i)
            if gate.get('decision') == 'DISAGREE' or (d and d.get('decision') == 'DISAGREE'):
                alt = (d or {}).get('alternative') if d and d.get('decision') == 'DISAGREE' else rec.get('alternative')
                sent_back.add(i)
                data['dissent'].append({'item': i, 'by': approver, 'alternative': alt or '',
                                        'review_id': p.get('review_id')})
    # ── item-level separation of duties ──────────────────────────────────────────────────────────
    for i, it in enumerate(p['items']):
        if i in sent_back or not approver:
            continue
        roles = {'requester': it.get('requested_by') or (it.get('finding') or {}).get('requested_by')}
        if template == 'triage':
            roles = {'triager': it.get('triaged_by')}
        if template == 'closure':
            roles = {}          # the fixer's own verification is PENDING, decided below -- never refused
            if it['action'] == 'reject' and sod.violations({'fixer': it['fixed_by']}, approver):
                roles = {'fixer': it['fixed_by']}
        viol = sod.violations(roles, approver) if any(roles.values()) else []
        if viol:
            return _refused('API_TEMPLATE_RULE_REFUSED', tt.refusal(tt.SOD_SELF_APPROVAL, 'item %d: %s -- nobody '
                            'approves their own work' % (i, sod.describe(viol)), i), data)

    stamp = (getattr(backend, 'stamp_label', '') or rt.DEFAULT_STAMP_LABEL) if backend is not None else 'secure-cicd-kit'
    plan = Plan()
    for i in sorted(sent_back):
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_SENT_BACK, 'dissent': data['dissent'][-1]['alternative']
                           if data['dissent'] else '', 'detail': 'the concurring reviewer DISAGREED; the item goes back '
                           'to the submitter with the dissent recorded'})
    live = [i for i in range(len(p['items'])) if i not in sent_back]
    if not live:
        data['items'] = plan.items
        return ANSWER_COMPLETED, data, ['every item was sent back with the dissent'], 'DECISION_REQUIRED', None

    # ── is the tracker there at all? ─────────────────────────────────────────────────────────────
    why_down = ''
    if backend is None:
        why_down = 'no ticket backend is configured'
    elif hasattr(backend, 'validate'):
        if hasattr(backend, 'set_routing'):
            backend.set_routing(ctx.get('routing'), ctx['repo'], sorted(set(
                str(e.get('project')) for e in (ledger or {}).values() if isinstance(e, dict) and e.get('project'))))
        ok, vdetail = backend.validate()
        if not ok:
            why_down = 'the tracker could not be validated: %s' % vdetail
    elif getattr(backend, 'name', '') == 'github' and hasattr(backend, 'probe'):
        ok, vdetail = backend.probe()
        if not ok:
            why_down = 'the tracker could not be validated: %s' % vdetail
    sweep_map, complete = {}, False
    if not why_down:
        known = sorted(set(str(e.get('ref')) for e in (ledger or {}).values() if isinstance(e, dict) and e.get('ref')))
        sweep_map, complete, sdetail = backend.sweep(known_refs=known)
        data['sweep'] = sdetail
        if not complete:
            why_down = 'the kit\'s stamp sweep did not complete: %s' % sdetail
    if why_down:
        return _outbox(ctx, p, data, plan, live, why_down)

    if not dry:
        dedupe_pending_pass(data, backend, sweep_map, today, True)
    adapter = ti.adapter_for(backend)
    data['intake_adapter'] = adapter.name
    ck_prefix = _lab(stamp, 'ck-')
    numbers = ctx.get('numbers')
    prov = {'submitted_by': actor.get('actor') or '', 'on_behalf_of': actor.get('on_behalf_of') or '',
            'review_id': p.get('review_id') or '', 'correlation_id': ctx.get('correlation_id') or ''}
    trust_ctx = {'approved_tools': ctx.get('approved_tools') or [], 'evidence_stores': ctx.get('evidence_stores') or [],
                 'review_finalized': bool(gate and gate['state'] == rf.REVIEW_FINALIZED),
                 'submitter_verified': bool(actor.get('actor'))}
    decisions = dict((d['correlation_key'], d) for d in p.get('link_decisions') or [])

    if template in tt.FINDING_BEARING:
        r = _plan_findings(ctx, p, plan, live, stamp, ck_prefix, sweep_map, adapter, decisions, prov, trust_ctx, numbers)
    else:
        r = _plan_updates(ctx, p, plan, live, stamp, ck_prefix, sweep_map, approver, data)
    if r:
        return _refused('API_TEMPLATE_RULE_REFUSED', r, data)

    failed = _write(ctx, p, plan, stamp, ck_prefix, approver, approval, dry, data)
    result = None
    if plan.to_reconcile:
        clusters, withheld = rt.build_clusters(plan.to_reconcile)
        context = {'coverage': None, 'numbers': numbers, 'run_url': ctx.get('run_url') or '',
                   'commit': ctx.get('commit') or '', 'routing': ctx.get('routing'), 'repository': ctx['repo'],
                   'exceptions': rt.exceptions_from_registrations(ctx.get('central'), ctx.get('repo_reg'))}
        result = rt.reconcile(clusters, withheld, backend, ledger, not dry, approval=approval, today=today,
                              context=context)
        made = dict((c['cluster_key'], c) for c in result.get('created') or [])
        keys = dict((k, (e or {}).get('key')) for k, e in ledger.items() if isinstance(e, dict))
        down = []
        for pi in plan.items:
            if pi.get('outcome') not in ('reconcile', 'reconcile-possible', 'reconcile-pending'):
                continue
            c = made.get(pi['correlation_key'])
            if c:
                final = {'reconcile': tt.TEMPLATE_TICKET_CREATED, 'reconcile-possible': tt.TEMPLATE_POSSIBLE_DUPLICATE,
                         'reconcile-pending': tt.TEMPLATE_DEDUPE_PENDING}[pi['outcome']]
                pi.update(outcome=tt.TEMPLATE_TICKET_PLANNED if c.get('planned') else final, ref=c.get('ref') or '',
                          key=keys.get(pi['correlation_key']) or '', title=c.get('title'),
                          ticket_class=c.get('ticket_class'))
            else:
                down.append(pi['item'])
        for kind, ck, payload in plan.post:
            pi = [x for x in plan.items if x.get('correlation_key') == ck]
            if dry or not pi or not pi[0].get('ref'):
                continue
            if kind == 'possible':
                backend.comment(pi[0]['ref'], 'POSSIBLE DUPLICATE (secure-cicd-kit): this may be the same finding as %s '
                                '-- %s. It is NOT merged; a person decides merge or separate (template triage).'
                                % (', '.join(c['key'] or c['ref'] for c in payload), '; '.join(
                                    '%s by %s' % (c['key'] or c['ref'], c['basis']) for c in payload)))
            elif kind == 'pending':
                backend.comment(pi[0]['ref'], 'DEDUPE PENDING (secure-cicd-kit): the search of every ticket did not '
                                'complete (%s), so this ticket was created in triage rather than lost; its dedupe is '
                                're-run on the next run.' % payload)
        if not dry:
            _after_create(ctx, p, plan, stamp, data)
        if down:
            # A RECONCILER THAT COULD NOT CREATE IS AN UNREACHABLE TRACKER for those items: the outbox.
            return _outbox(ctx, p, data, plan, down, 'the reconciler could not create: %s' % '; '.join(
                str(o.get('cause')) for o in result.get('obligations') or [])[:400], partial=True)
        if not dry:
            _save(ctx, 'ticket-ledger-proposal.json', {'schema': 1, 'clusters': ledger})
        data['reconcile'] = {'outcomes': result.get('outcomes'), 'created': result.get('created'),
                             'updated': result.get('updated'), 'needs_decision': result.get('needs_decision'),
                             'obligations': result.get('obligations'), 'ticketing_state': result.get('ticketing_state')}
    if failed:
        return _outbox(ctx, p, data, plan, sorted(set(f[0] for f in failed)), '; '.join(f[1] for f in failed)[:400],
                       partial=True)
    data['items'] = sorted(plan.items, key=lambda x: (x.get('item', 0), x.get('correlation_key') or ''))
    claim = ((result or {}).get('ticketing_claim') or {}).get('routing_result') or 'PROCEED'
    return ANSWER_COMPLETED, data, ['a request is not a disposition: nothing stops blocking until an approved '
                                    'disposition is merged to the protected default branch'], claim, None


def _has(labels, name):
    """A label is on the ticket, compared as the tracker stores it (a GitHub label is cut to 50 characters)."""
    import reconcile_tickets as rt
    return name in labels or rt.fit_label(name) in labels


def _base(rec, conf, trust):
    return {'correlation_key': rec['correlation_key'], 'confidence': conf[0], 'confidence_basis': conf[1],
            'trust': trust[0], 'trust_basis': trust[1]}


def _plan_findings(ctx, p, plan, live, stamp, ck_prefix, sweep_map, adapter, decisions, prov, trust_ctx, numbers):
    backend, template, settings, today = ctx['backend'], p['template'], ctx['settings'], ctx['today']
    recs = [tt.normalize(template, p['items'][i], prov, i, stamp, settings, today, numbers) for i in live]
    if p.get('via'):
        # KDEC-043 rule 2: the via label is a CLAIM, set at creation; _after_create compares it with what was proven.
        for rec in recs:
            rec['template_labels'] = sorted(set(rec['template_labels']) | {tg.via_label(stamp, p['via'])})
    groups = {}
    for rec in recs:
        groups.setdefault(rec['correlation_key'], []).append(rec)
    for ck, grp in sorted(groups.items()):
        corr = fc.correlate(grp)
        conf = fc.corroboration_score(corr['clusters'][0], grp)
        trust = tt.trust_score(grp[0], trust_ctx)
        for g in grp:
            g['template_facts'] = list(g['template_facts']) + [
                ('confidence score', '%s -- %s' % (conf[0], conf[1])), ('trust score', '%s -- %s' % (trust[0], trust[1]))]
        rec0 = grp[0]
        if template == 'finding':
            _fp_recheck(ctx, plan, rec0, sweep_map, stamp)
        hits = sweep_map.get(ck) or []
        target, basis = None, ''
        cands = []
        state, sdetail = ti.TRACKER_INTAKE_COMPLETE, ''
        if hits:
            target, basis = dict(hits[0]), 'stamp'
        else:
            if hasattr(adapter, 'search_all'):
                tickets, state, sdetail = adapter.search_all(text=rec0.get('rule'), ck_label=ck_prefix + ck)
            else:
                tickets, state, sdetail = [], ti.TRACKER_INTAKE_NOT_CONFIGURED, adapter.search()['detail']
            if state == ti.TRACKER_INTAKE_COMPLETE:
                pool = list(tickets)
                m = ti.match(dict(rec0), pool, ck_prefix + ck, 'secure-cicd-kit-cluster:', settings['fuzzy_title_percent'])
                cands = [{'ref': t['ref'], 'key': t.get('key'), 'basis': b, 'score': s, 'summary': t.get('summary'),
                          'labels': t.get('labels'), 'state': t.get('state')} for t, b, s in m['candidates']]
                if m['exact']:
                    t0, basis = m['exact'][0]
                    # A ticket the kit stamped is the kit's own even when the stamp sweep had not caught up with it
                    # yet (GitHub's label listing is eventually consistent): never "manual", never labelled linked.
                    target = {'ref': t0['ref'], 'key': t0.get('key'), 'labels': t0.get('labels'), 'state': t0.get('state'),
                              'manual': not t0.get('stamp')}
        dec = decisions.get(ck)
        if target is None and cands and dec and dec['decision'] == 'link':
            c = [x for x in cands if dec.get('ref') in (x['ref'], x['key'])]
            if not c:
                return tt.refusal(tt.LINK_DECISION_INVALID, 'the link decision for %s names %s, which is not a '
                                  'candidate (candidates: %s)' % (ck, dec.get('ref'), ', '.join(x['ref'] for x in cands)),
                                  grp[0]['item'])
            target, basis = dict(c[0], manual=True), 'confirmed-candidate (%s)' % c[0]['basis']
        elif target is None and dec and dec['decision'] == 'link':
            return tt.refusal(tt.LINK_DECISION_INVALID, 'the link decision for %s names %s and there is no candidate'
                              % (ck, dec.get('ref')), grp[0]['item'])
        if target is not None:
            _plan_exact(ctx, plan, grp, target, basis, stamp, conf, trust)
            continue
        if state != ti.TRACKER_INTAKE_COMPLETE:
            for g in grp:
                g['template_labels'] = sorted(set(g['template_labels']) | {_lab(stamp, 'dedupe-pending'),
                                                                            _lab(stamp, 'triage')})
            plan.to_reconcile.extend(grp)
            plan.post.append(('pending', ck, sdetail))
            for g in grp:
                plan.items.append(dict(_base(g, conf, trust), item=g['item'], outcome='reconcile-pending',
                                       intake_state=state, detail=sdetail))
            continue
        if cands and not (dec and dec['decision'] == 'new'):
            for g in grp:
                g['template_labels'] = sorted(set(g['template_labels']) | {_lab(stamp, 'possible-duplicate'),
                                                                            _lab(stamp, 'triage')})
            plan.to_reconcile.extend(grp)
            plan.post.append(('possible', ck, cands))
            for g in grp:
                plan.items.append(dict(_base(g, conf, trust), item=g['item'], outcome='reconcile-possible',
                                       candidates=[dict((k, c[k]) for k in ('ref', 'key', 'basis', 'score', 'summary'))
                                                   for c in cands]))
            continue
        plan.to_reconcile.extend(grp)
        for g in grp:
            plan.items.append(dict(_base(g, conf, trust), item=g['item'], outcome='reconcile', title=g.get('title')))
    return None


def _plan_exact(ctx, plan, grp, target, basis, stamp, conf, trust):
    """An exact match: a closed duplicate, nothing (the same contribution again), a regression, or a no-fix
    ticket reopened as remediation."""
    rec0 = grp[0]
    labels = set(target.get('labels') or [])
    ev = _lab(stamp, 'ev-%s' % (rec0['provenance'].get('evidence_sha256') or '')[:16])
    tool = _lab(stamp, 'tool-%s' % tt._slug(rec0.get('tool')))
    closed = target.get('state') == 'closed'
    fixing = any(g.get('fix_status') == 'FIX_AVAILABLE' for g in grp) and rec0.get('template') == 'finding'
    if fixing and _has(labels, _lab(stamp, 'nofix')):
        outcome = tt.TEMPLATE_REOPENED_AS_REMEDIATION
        plan.actions.append(('remediate', {'target': target, 'grp': grp}))
    elif closed and rec0.get('template') == 'finding' and not _has(labels, ev):
        outcome = tt.TEMPLATE_REGRESSION
        plan.actions.append(('regression', {'target': target, 'grp': grp}))
    elif _has(labels, ev) or rec0.get('template') != 'finding':
        outcome = tt.TEMPLATE_LINKED_EXACT if target.get('manual') else tt.TEMPLATE_TICKET_BOUND
    else:
        tools = [x[len(_lab(stamp, 'tool-')):] for x in labels if x.startswith(_lab(stamp, 'tool-'))]
        before = confidence_for(tools, rec0.get('rule'))
        after = confidence_for(tools + [tt._slug(g.get('tool')) for g in grp], rec0.get('rule'))
        outcome = tt.TEMPLATE_CLOSED_DUPLICATE
        plan.actions.append(('duplicate', {'target': target, 'grp': grp, 'before': before, 'after': after,
                                           'new_tool': not _has(labels, tool)}))
    for g in grp:
        plan.items.append(dict(_base(g, conf, trust), item=g['item'], outcome=outcome,
                               ref=str(target.get('ref') or ''), key=target.get('key') or '', basis=basis,
                               original_ref=str(target.get('ref') or '')))


def _fp_recheck(ctx, plan, rec, sweep_map, stamp):
    """A false positive is re-checked when the rule, the tool version or the code changes."""
    import hashlib
    fp_ident = hashlib.sha256(('kit-request/1|false-positive|%s' % rec['identity']).encode()).hexdigest()[:32]
    del fp_ident
    fp_ck = fc.cluster_key(rec['finding_subject'], 'request:false-positive:%s' % rec['where'],
                           'request:false-positive:%s' % (rec['what_aliases'][0] if rec['what_aliases'] else ''))
    for hit in sweep_map.get(fp_ck) or []:
        if hit.get('ref') and _lab(stamp, 'fp-recheck') not in (hit.get('labels') or []):
            plan.actions.append(('fp-recheck', {'ref': hit['ref'], 'rec': rec}))


def _plan_updates(ctx, p, plan, live, stamp, ck_prefix, sweep_map, approver, data):
    backend, settings, today, template = ctx['backend'], ctx['settings'], ctx['today'], p['template']
    for i in live:
        it = p['items'][i]
        refs = [it['ref']] + ([it['original_ref']] if template == 'triage' else [])
        owned = {}
        for ref in refs:
            stampk = None
            for k, hits in sweep_map.items():
                if any(str(h.get('ref')) == str(ref) or (h.get('key') and str(h.get('key')) == str(ref)) for h in hits):
                    stampk = k
            labels, ok, detail = backend.labels_of(ref) if hasattr(backend, 'labels_of') else ([], False, 'no read')
            if not ok:
                return tt.refusal(tt.TICKET_NOT_KIT_LINKED, 'item %d: ticket %s could not be read (%s)' % (i, ref, detail), i)
            # A kit child obligation (KDEC-043 rule 4) names its parent; it carries no stamp of its own.
            mine = stampk or any(str(x).startswith(ck_prefix) for x in labels) or bool(tg.parent_of(labels, stamp))
            if not mine and not (template == 'triage' and ref == it.get('original_ref')):
                return tt.refusal(tt.TICKET_NOT_KIT_LINKED, 'item %d: ticket %s carries neither the kit\'s stamp nor a '
                                  'link to a kit finding' % (i, ref), i)
            owned[ref] = (labels, stampk)
        labels, stampk = owned[it['ref']]
        if template == 'extension':
            observed = tt.extensions_observed(labels, stamp)
            bad = tt.check_extension(it, i, observed, approver, settings)
            if bad:
                return bad
            plan.actions.append(('extend', {'it': it, 'n': observed + 1, 'labels': labels}))
            plan.items.append({'item': i, 'outcome': tt.TEMPLATE_TICKET_UPDATED, 'ref': it['ref'],
                               'extension': observed + 1})
        elif template == 'triage':
            plan.actions.append(('triage', {'it': it, 'labels': labels, 'original_labels': owned[it['original_ref']][0]}))
            plan.items.append({'item': i, 'ref': it['ref'], 'original_ref': it['original_ref'],
                               'outcome': tt.TEMPLATE_CLOSED_DUPLICATE if it['decision'] == 'merge'
                               else tt.TEMPLATE_TRIAGED_SEPARATE})
        else:
            r = _plan_closure(ctx, plan, i, it, labels, stampk, approver, data)
            if r:
                return r
    return None


def _plan_closure(ctx, plan, i, it, labels, stampk, approver, data):
    rt, settings, today, stamp = ctx['rt'], ctx['settings'], ctx['today'], (
        getattr(ctx['backend'], 'stamp_label', '') or 'secure-cicd-kit')
    action, kind = it['action'], it['verification']['kind']
    if action == 'verify' and (tg.children_of(labels, stamp) or tg.expected_children(labels, stamp)):
        # KDEC-043 rule 4: THE PARENT CLOSES ONLY WHEN EVERY CHILD OBLIGATION IS CLOSED-VERIFIED.
        ok_p, _open, why_p = tg.parent_may_close(ctx['backend'], labels, stamp)
        if not ok_p:
            return tt.refusal(tg.CHILD_OBLIGATION_OPEN, 'item %d: ticket %s: %s' % (i, it['ref'], why_p), i)
    if action == 'resolve' or (action == 'verify' and kind == 'reviewer' and
                               sod.violations({'fixer': it['fixed_by']}, approver)):
        note = '' if action == 'resolve' else 'the fixer\'s own verification is PENDING, never final'
        plan.actions.append(('resolve', {'it': it, 'note': note}))
        data['notifications'].append({'to': ctx.get('approver_source') or tt.DEFAULT_APPROVER_SOURCE, 'ref': it['ref'],
                                      'message': 'ready to close, please verify: ticket %s, resolved by %s'
                                      % (it['ref'], it['fixed_by'])})
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_PENDING_VERIFICATION, 'ref': it['ref'],
                           'detail': note or 'resolved by the fixer; someone else verifies'})
        return None
    if action == 'reject':
        plan.actions.append(('reject', {'it': it}))
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_VERIFICATION_REJECTED, 'ref': it['ref']})
        return None
    if kind == 'reviewer':
        plan.actions.append(('close', {'it': it, 'by': 'reviewer %s' % approver}))
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_TICKET_CLOSED, 'ref': it['ref'],
                           'verified_by': 'reviewer %s' % approver})
        return None
    # A RESCAN: the kit's own scan, on the branch mapped to the ticket's environment.
    entry = ctx['ledger'].get(stampk) if stampk and isinstance(ctx['ledger'].get(stampk), dict) else {}
    if not entry.get('members'):
        return tt.refusal(tt.CLOSURE_NOT_VERIFIED, 'item %d: the kit\'s own scan never observed this ticket\'s finding '
                          '(no ledger record of which scanner saw it), so no rescan can verify it: a reviewer confirms'
                          % i, i)
    run, recs, cov, ref2 = ctx['evidence'](it['verification']['run_id'], True)
    if ref2:
        return tt.refusal(tt.CLOSURE_NOT_VERIFIED, 'item %d: %s' % (i, ref2['detail']), i)
    present = set(x.get('identity') for x in recs if x.get('identity'))
    if present & set(entry.get('member_identities') or []):
        return tt.refusal(tt.CLOSURE_NOT_VERIFIED, 'item %d: run %s still reports the finding' % (i, run.get('id')), i)
    covmap = (dict((r2['scanner'], r2) for r2 in (cov or {}).get('rows') or [] if isinstance(r2, dict) and
                   r2.get('scanner')) if isinstance(cov, dict) else None)
    _ev, gaps = rt.clearance_gaps(entry, covmap, [x for x in recs if not x.get('identity')])
    if gaps:
        return tt.refusal(tt.CLOSURE_NOT_VERIFIED, 'item %d: %s' % (i, '; '.join(gaps)), i)
    branch = run.get('head_branch') or ''
    envs = [x[len('%s-env-' % stamp):] for x in labels if str(x).startswith('%s-env-' % stamp)]
    mapped = tt.branch_environment(branch, ctx.get('branch_map') or '', ctx['default_branch'])
    closes = (mapped is not None and (mapped in envs or (not envs and branch == ctx['default_branch'])))
    if closes:
        plan.actions.append(('close', {'it': it, 'by': 'the kit\'s rescan, run %s on %s' % (run.get('id'), branch)}))
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_TICKET_CLOSED, 'ref': it['ref'],
                           'verified_by': 'rescan %s on %s' % (run.get('id'), branch)})
    else:
        plan.actions.append(('observed', {'it': it, 'branch': branch, 'run': run.get('id'),
                                          'needs': ', '.join(envs) or ctx['default_branch']}))
        plan.items.append({'item': i, 'outcome': tt.TEMPLATE_FIX_OBSERVED, 'ref': it['ref'], 'branch': branch})
    return None


def _write(ctx, p, plan, stamp, ck_prefix, approver, approval, dry, data):
    """-> [(item index, why)] for every write that failed (they go to the outbox)."""
    backend, today, settings = ctx['backend'], ctx['today'], ctx['settings']
    failed = []
    review = p.get('review_id') or 'no review'

    def ok_all(*rs):
        return all(r[0] for r in rs)
    for kind, a in plan.actions:
        if dry:
            for pi in plan.items:
                pi['planned'] = True
            continue
        if kind == 'duplicate':
            t, grp = a['target'], a['grp']
            g0 = grp[0]
            added = ['- source: %s via %s' % (g0.get('source_type'), g0.get('tool')),
                     '- evidence: %s (sha256 %s)' % (g0['provenance'].get('evidence_ref'),
                                                     g0['provenance'].get('evidence_sha256')),
                     '- asset / location: %s' % g0.get('uri'), '- severity: %s' % g0.get('severity')]
            if a['new_tool']:
                added.append('- confidence increased %d -> %d (%s)' % (a['before'][0], a['after'][0], a['after'][1]))
            text = '\n'.join(added)
            dref, dd = backend.create_instance(t['ref'], {'identity': g0['identity']},
                                               ctx['rt'].duplicate_body(t.get('key') or t['ref'], g0['correlation_key'],
                                                                        text),
                                               ctx['rt'].bounded_title('[duplicate] %s' % (g0.get('title') or g0.get('rule'))))
            if not dref:
                failed.append((g0['item'], 'the duplicate record under %s was not created: %s' % (t['ref'], dd)))
                continue
            backend.mark(dref, labels=[_lab(stamp, 'duplicate')])
            backend.close(dref)
            sev_note = ''
            sevs = [x[len(_lab(stamp, 'sev-')):] for x in t.get('labels') or [] if str(x).startswith(_lab(stamp, 'sev-'))]
            if sevs and g0.get('severity') not in sevs:
                sev_note = ' Severity change: %s -> %s.' % ('/'.join(sevs), g0.get('severity'))
            r1 = backend.comment(t['ref'], 'DUPLICATE recorded (secure-cicd-kit, review %s): %s is a duplicate of this '
                                 'ticket and is closed. What it added:\n%s%s' % (review, dref, text, sev_note))
            r2 = backend.mark(t['ref'], labels=[_lab(stamp, 'tool-%s' % tt._slug(g0.get('tool'))),
                                                _lab(stamp, 'src-%s' % tt._slug(g0.get('source_type'))),
                                                _lab(stamp, 'ev-%s' % (g0['provenance'].get('evidence_sha256') or '')[:16]),
                                                _lab(stamp, 'sev-%s' % tt._slug(g0.get('severity')))] +
                             ([ck_prefix + g0['correlation_key'], _lab(stamp, 'linked')] if t.get('manual') else []))
            r3 = (True, '')
            if t.get('manual'):
                # KDEC-043: the label is a search aid; the FULL key goes in the kit's own block on the person's
                # ticket, so the next lookup verifies the label against it instead of trusting the label.
                r3 = tg.write_link(backend, t['ref'], g0['correlation_key'])
            for pi in plan.items:
                if pi.get('correlation_key') == g0['correlation_key']:
                    pi['duplicate_ref'] = dref
            if not ok_all(r1, r2, r3):
                failed.append((g0['item'], 'the original %s was not updated' % t['ref']))
        elif kind == 'regression':
            t, g0 = a['target'], a['grp'][0]
            ok_r, why = backend.reopen(t['ref'])
            backend.comment(t['ref'], 'REGRESSION (secure-cicd-kit, review %s): this finding was closed and is newly '
                            'observed by %s (%s). Reopened as a regression, not a duplicate.%s'
                            % (review, g0.get('tool'), g0['provenance'].get('evidence_ref'),
                               '' if ok_r else ' The reopen was refused (%s): a person reopens it.' % why))
            backend.mark(t['ref'], labels=[_lab(stamp, 'regression'),
                                           _lab(stamp, 'ev-%s' % (g0['provenance'].get('evidence_sha256') or '')[:16]),
                                           _lab(stamp, 'tool-%s' % tt._slug(g0.get('tool')))])
        elif kind == 'remediate':
            t = a['target']
            if t.get('state') == 'closed' and not tm.authorise('ticket.reopen_as_remediation', approval):
                ok_r, why = backend.reopen(t['ref'])
                if not ok_r:
                    failed.append((a['grp'][0]['item'], 'ticket %s could not be reopened as remediation: %s'
                                   % (t['ref'], why)))
                    continue
            backend.comment(t['ref'], 'A FIX IS NOW AVAILABLE (secure-cicd-kit, review %s): this finding had no fix '
                            'upstream; it is now FIX_AVAILABLE, so this ticket is REMEDIATION work again and its no-fix '
                            'exemption no longer applies.' % review)
            backend.mark(t['ref'], labels=[_lab(stamp, 'fix-available')])
        elif kind == 'fp-recheck':
            desc, ok, _d = backend.read_description(a['ref'])
            text = backend.description_text(desc) if ok else ''
            facts = {'tool version': _row(text, 'tool version'), 'code ref': _row(text, 'code ref'),
                     'rule': _row(text, 'rule')}
            why = tt.fp_recheck_reason(facts, a['rec'])
            if why:
                backend.comment(a['ref'], 'FALSE POSITIVE RE-CHECK (secure-cicd-kit, review %s): %s. A false positive '
                                'has no expiry; it is re-checked when the rule, the tool version or the code changes. '
                                'A reviewer confirms it still holds.' % (review, why))
                backend.mark(a['ref'], labels=[_lab(stamp, 'fp-recheck')])
        elif kind == 'extend':
            it, n = a['it'], a['n']
            exp = it.get('new_expiry') or (datetime.date.fromisoformat(today) +
                                           datetime.timedelta(days=settings['extension_default_days'])).isoformat()
            if tm.authorise('task.deferral.extend', approval):
                failed.append((0, 'the extension of %s was not authorised' % it['ref']))
                continue
            vendor = it.get('waiting_on') == 'vendor'
            r1 = backend.comment(it['ref'], (
                'EXTENSION %d%s (secure-cicd-kit, review %s): the new expiry is %s. Waiting on: %s. Reason: %s. Requested '
                'by %s; approved by %s, who is not the requester. Evidence: %s (sha256 %s).'
                % (n, '' if vendor else ' of %d' % settings['extension_max'], review, exp,
                   'the vendor (extensions continue until the vendor has a fix)' if vendor else 'a fix that is available',
                   it['reason'], it['requested_by'], approver, it['evidence']['ref'], it['evidence']['sha256'])))
            add = [_lab(stamp, 'extension-%d' % n)]
            since = tt.label_dates(a['labels'], stamp, 'extended-since')
            if not since:
                add.append(tt.date_label(stamp, 'extended-since', today))
            r2 = backend.mark(it['ref'], labels=add)
            first = since[0] if since else today
            days = (datetime.date.fromisoformat(today) - datetime.date.fromisoformat(first)).days
            if vendor and not _has(a['labels'] or [], _lab(stamp, 'vendor-advisory')) and (
                    n >= settings['vendor_advisory_extensions'] or days >= settings['vendor_advisory_days']):
                backend.comment(it['ref'], 'VENDOR ADVISORY (secure-cicd-kit): extension %d, %d day(s) since the first: '
                                'no fix after 6 months is coming -- consider an alternative.' % (n, days))
                backend.mark(it['ref'], labels=[_lab(stamp, 'vendor-advisory')])
            if not ok_all(r1, r2[:2]):
                failed.append((0, 'the extension of %s was not written' % it['ref']))
        elif kind == 'resolve':
            it = a['it']
            r1 = backend.comment(it['ref'], 'RESOLVED - PENDING VERIFICATION (secure-cicd-kit): %s says the fix is done '
                                 '(evidence %s, sha256 %s). Ready to close, please verify: the approver list (%s), '
                                 'someone other than the fixer, or the kit\'s rescan.%s'
                                 % (it['fixed_by'], it['evidence']['ref'], it['evidence']['sha256'],
                                    ctx.get('approver_source') or tt.DEFAULT_APPROVER_SOURCE,
                                    (' (%s.)' % a['note']) if a['note'] else ''))
            r2 = backend.mark(it['ref'], labels=[_lab(stamp, 'pending-verification'),
                                                 tt.date_label(stamp, 'pending-since', today)])
            if not ok_all(r1, r2[:2]):
                failed.append((0, 'ticket %s was not moved to pending verification' % it['ref']))
        elif kind == 'reject':
            it = a['it']
            if tm.authorise('ticket.verification_reject', approval):
                failed.append((0, 'the rejection of %s was not authorised' % it['ref']))
                continue
            labels, _ok, _d = backend.labels_of(it['ref'])
            backend.reopen(it['ref'])
            backend.comment(it['ref'], 'VERIFICATION REJECTED (secure-cicd-kit, review %s) by %s: %s. The ticket is open '
                            'again; the fixer resolves it again when it is done.' % (review, approver, it['reason']))
            backend.mark(it['ref'], labels=[_lab(stamp, 'verification-rejected'), tt.date_label(stamp, 'rejected', today)])
        elif kind == 'close':
            it = a['it']
            mut = 'ticket.close.reviewer_confirmed' if it['verification']['kind'] == 'reviewer' else \
                'ticket.close.' + tm.ALL_CHILDREN_RESOLVED
            if tm.authorise(mut, approval):
                failed.append((0, 'the closure of %s was not authorised' % it['ref']))
                continue
            ok_x, d_x = backend.close(it['ref'])
            if not ok_x:
                failed.append((0, 'ticket %s could not be closed: %s' % (it['ref'], d_x)))
                continue
            backend.comment(it['ref'], 'CLOSED - VERIFIED (secure-cicd-kit, %s): verified by %s; fixed by %s; evidence %s '
                            '(sha256 %s). The fixer did not verify it.' % (review, a['by'], it['fixed_by'],
                                                                           it['evidence']['ref'], it['evidence']['sha256']))
            backend.mark(it['ref'], labels=[_lab(stamp, 'verified'), _lab(stamp, 'remediated')])
            child_labels, ok_cl, _d_cl = backend.labels_of(it['ref'])
            parent = tg.parent_of(child_labels, stamp) if ok_cl else ''
            if parent:
                _close_parent_if_done(backend, parent, it['ref'], stamp, review, approval, data)
        elif kind == 'observed':
            it = a['it']
            backend.comment(it['ref'], 'FIX OBSERVED on %s (secure-cicd-kit): run %s no longer reports the finding there. '
                            'It closes when the fix reaches the branch mapped to this ticket\'s environment (%s).'
                            % (a['branch'], a['run'], a['needs']))
            backend.mark(it['ref'], labels=[_lab(stamp, 'fix-observed-%s' % tt._slug(a['branch']))])
        elif kind == 'triage':
            it = a['it']
            if tm.authorise('ticket.triage_merge', approval):
                failed.append((0, 'the triage of %s was not authorised' % it['ref']))
                continue
            if it['decision'] == 'merge':
                carry = [x for x in a['labels'] if any(str(x).startswith(_lab(stamp, w))
                                                       for w in ('tool-', 'src-', 'ev-'))]
                backend.comment(it['ref'], 'TRIAGED: DUPLICATE of %s (secure-cicd-kit, review %s; triaged by %s, '
                                'concurred by %s): %s. Closed as a duplicate.' % (it['original_ref'], review,
                                                                                  it['triaged_by'], approver, it['reason']))
                backend.mark(it['ref'], labels=[_lab(stamp, 'duplicate')])
                ok_x, d_x = backend.close(it['ref'])
                backend.comment(it['original_ref'], 'TRIAGED (secure-cicd-kit, review %s): %s was a duplicate of this '
                                'ticket and is closed; it added %s.' % (review, it['ref'], ', '.join(carry) or 'no new source'))
                backend.mark(it['original_ref'], labels=carry + [_lab(stamp, 'linked')])
                if not ok_x:
                    failed.append((0, 'ticket %s could not be closed as a duplicate: %s' % (it['ref'], d_x)))
            else:
                backend.comment(it['ref'], 'TRIAGED: SEPARATE from %s (secure-cicd-kit, review %s; triaged by %s, '
                                'concurred by %s): %s.' % (it['original_ref'], review, it['triaged_by'], approver,
                                                           it['reason']))
                backend.mark(it['ref'], labels=[_lab(stamp, 'triaged-separate')])
    return failed


# ═════════════════════════════════════════════════════════════════════════════════════
# KDEC-043: PROVENANCE AND CHILD OBLIGATIONS, after the reconciler created
# ═════════════════════════════════════════════════════════════════════════════════════

_CREATED = (tt.TEMPLATE_TICKET_CREATED, tt.TEMPLATE_POSSIBLE_DUPLICATE, tt.TEMPLATE_DEDUPE_PENDING)


def _after_create(ctx, p, plan, stamp, data):
    recs = {}
    for r in plan.to_reconcile:
        recs.setdefault(r['correlation_key'], r)
    done = {}
    for pi in plan.items:
        ref, ck = pi.get('ref'), pi.get('correlation_key')
        if not ref or pi.get('outcome') not in _CREATED:
            continue
        if (ck, ref) not in done:
            got = {'provenance': _provenance(ctx, p, ref, stamp, data)}
            rec = recs.get(ck) or {}
            if rec.get('obligations'):
                got['children'] = _children(ctx, rec, ref, stamp, data)
            done[(ck, ref)] = got
        pi.update(done[(ck, ref)])


def _provenance(ctx, p, ref, stamp, data):
    """KDEC-043 rule 2: the via CLAIM against the authenticated identity and the tracker's own record of the write."""
    backend = ctx['backend']
    claimed = p.get('via') or ''
    ident = backend.authenticated_identity() if hasattr(backend, 'authenticated_identity') else None
    actor, detail = backend.write_event(ref) if hasattr(backend, 'write_event') else (
        None, 'this tracker adapter reads no write event')
    rec = tg.provenance(claimed, ident, actor, ctx.get('integrations') or {})
    rec['write_event_detail'] = detail
    if rec['state'] == tg.PROVENANCE_MISMATCH or (claimed and rec['state'] == tg.PROVENANCE_NOT_ESTABLISHED):
        word = 'provenance-mismatch' if rec['state'] == tg.PROVENANCE_MISMATCH else 'provenance-unverified'
        backend.comment(ref, '%s (secure-cicd-kit): %s. The via label on this ticket is a claim; a person checks who '
                             'wrote it.' % (rec['state'], '; '.join(rec['reasons']) or 'not established'))
        backend.mark(ref, labels=[_lab(stamp, word)])
        data['alerts'].append('%s on ticket %s: %s' % (rec['state'], ref, '; '.join(rec['reasons'])))
    return rec


def _children(ctx, rec, parent_ref, stamp, data):
    """KDEC-043 rule 4: one child obligation per cloud asset, under the parent, each with its own owner role."""
    rt, backend = ctx['rt'], ctx['backend']
    out = []
    for ob in rec['obligations']:
        labels = [tg.obligation_label(stamp, ob['id']), tg.owner_label(stamp, ob['owner_role']),
                  tg.parent_label(stamp, parent_ref)]
        body = '\n'.join([
            'Child obligation %s of %s (secure-cicd-kit, KDEC-043): %s, %s.' % (ob['id'], parent_ref, ob['cloud'],
                                                                              ob['display']),
            '', 'Owner role: %s.' % ob['owner_role'],
            'Closes ONLY by the kit\'s rescan or a verification by someone other than the fixer (template closure,',
            'on this ticket). The parent closes when every child obligation is closed-verified.', '',
            'secure-cicd-kit-obligation-of: %s' % rec['correlation_key']])
        title = rt.bounded_title('[%s obligation %s] %s' % (ob['cloud'], ob['id'], rec.get('title') or rec.get('rule')))
        cref, d = backend.create_instance(parent_ref, {'identity': '%s:%s' % (rec['identity'], ob['id']),
                                                       'labels': labels}, body, title)
        if not cref:
            data['alerts'].append('CHILD OBLIGATION NOT CREATED: %s of ticket %s (%s); the parent cannot close until '
                                  'it exists' % (ob['id'], parent_ref, d))
            out.append({'id': ob['id'], 'cloud': ob['cloud'], 'owner_role': ob['owner_role'], 'ref': None, 'detail': d})
            continue
        backend.mark(cref, labels=labels)
        backend.mark(parent_ref, labels=[tg.child_label(stamp, ob['id'], cref)])
        out.append({'id': ob['id'], 'cloud': ob['cloud'], 'owner_role': ob['owner_role'], 'ref': cref})
    return out


def _close_parent_if_done(backend, parent, child, stamp, review, approval, data):
    labels, ok, d = backend.labels_of(parent)
    if not ok:
        data['alerts'].append('the parent %s of %s could not be read (%s): it stays open' % (parent, child, d))
        return
    ok_p, open_, why = tg.parent_may_close(backend, labels, stamp)
    if not ok_p:
        backend.comment(parent, 'CHILD OBLIGATION CLOSED (secure-cicd-kit, review %s): %s is closed-verified. %s.'
                        % (review, child, why))
        return
    if tm.authorise('ticket.close.' + tm.ALL_CHILDREN_RESOLVED, approval):
        data['alerts'].append('the parent %s was not closed: the closure was not authorised' % parent)
        return
    ok_x, d_x = backend.close(parent)
    if not ok_x:
        data['alerts'].append('the parent %s could not be closed: %s' % (parent, d_x))
        return
    backend.comment(parent, 'CLOSED - EVERY CHILD OBLIGATION VERIFIED (secure-cicd-kit, review %s): %s.'
                    % (review, why))
    backend.mark(parent, labels=[_lab(stamp, 'verified'), _lab(stamp, 'remediated')])
    data.setdefault('parents_closed', []).append(parent)


# ═════════════════════════════════════════════════════════════════════════════════════
# THE OUTBOX: nothing is lost when the tracker is not there
# ═════════════════════════════════════════════════════════════════════════════════════

OUTBOX_SCHEMA = 'kit-ticket-outbox/1'


def _save(ctx, name, doc):
    d = ctx.get('out_dir')
    if d:
        os.makedirs(d, exist_ok=True)
        io.open(os.path.join(d, name), 'w', encoding='utf-8').write(json.dumps(doc, indent=2, sort_keys=True) + '\n')


def _outbox(ctx, p, data, plan, idxs, why, partial=False):
    """The items `idxs` could not be written: a durable outbox record (out_dir/outbox.json, kept by the workflow as
    the artifact kit-ticket-outbox-<correlation id> for 90 days), an alert, and a retry by a later run."""
    done = set(x['item'] for x in plan.items if x.get('outcome') in tt.TERMINAL_OUTCOMES)
    held = [i for i in idxs if i not in done]
    doc = {'schema': OUTBOX_SCHEMA, 'correlation_id': ctx.get('correlation_id') or '', 'created_at': ctx.get('now') or '',
           'reason': why, 'items': held, 'params': p, 'repository': ctx.get('repo')}
    _save(ctx, 'outbox.json', doc)
    keep = [x for x in plan.items if x['item'] not in held and x.get('outcome') in tt.TERMINAL_OUTCOMES]
    for i in held:
        keep.append({'item': i, 'outcome': tt.TEMPLATE_OUTBOX, 'detail': why})
    data['items'] = sorted(keep, key=lambda x: x.get('item', 0))
    data['outbox'] = {'entries': len(held), 'reason': why, 'artifact': 'kit-ticket-outbox-%s' % doc['correlation_id']}
    data['alerts'].append('TRACKER NOT WRITTEN: %d item(s) are held in the outbox (%s) and are retried by the next '
                          'run; a person is alerted. Nothing was lost.' % (len(held), why))
    return ANSWER_FAILED, data, ['outbox: %s' % why], 'EVIDENCE_UNTRUSTED', None


def drain_outbox(ctx, client, repo, run_submit):
    """-> [correlation ids drained]. Every outbox artifact of an earlier run with no done marker is re-submitted
    (the review is re-checked: the record is still on the default branch). A drained id goes in out_dir/
    outbox-done.json, kept as kit-ticket-outbox-done-<this correlation id>."""
    if client is None:
        return []
    st, doc, _h, err = client.get('/repos/%s/actions/artifacts?per_page=100' % repo)
    if err or not isinstance(doc, dict):
        return []
    arts = [a for a in doc.get('artifacts') or [] if not a.get('expired')]
    done = set()
    for a in arts:
        if str(a.get('name') or '').startswith('kit-ticket-outbox-done-'):
            blob = client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, a['id']))
            for name, raw in _zip_members(blob):
                if name.endswith('outbox-done.json'):
                    try:
                        done |= set(json.loads(raw.decode('utf-8')).get('drained') or [])
                    except ValueError:
                        pass
    drained = []
    for a in arts:
        name = str(a.get('name') or '')
        if not name.startswith('kit-ticket-outbox-') or name.startswith('kit-ticket-outbox-done-'):
            continue
        cid = name[len('kit-ticket-outbox-'):]
        if cid in done or cid == ctx.get('correlation_id'):
            continue
        blob = client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, a['id']))
        for fname, raw in _zip_members(blob):
            if not fname.endswith('outbox.json'):
                continue
            try:
                entry = json.loads(raw.decode('utf-8'))
            except ValueError:
                continue
            if entry.get('schema') != OUTBOX_SCHEMA:
                continue
            state, _d, _n, _rr, _ref = run_submit(entry['params'])
            if state == ANSWER_COMPLETED:
                drained.append(cid)
    if drained:
        _save(ctx, 'outbox-done.json', {'drained': sorted(set(drained) | done)})
    return drained


def _zip_members(blob):
    import zipfile
    try:
        z = zipfile.ZipFile(io.BytesIO(blob or b''))
    except zipfile.BadZipFile:
        return []
    return [(n, z.read(n)) for n in z.namelist()]
