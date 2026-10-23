#!/usr/bin/env python3
"""Resurface every exception as it comes due -- onto its ticket, saying plainly it was excepted before.
(KDEC-018 item 4, owner 2026-10-22: "have a timing mechanism to resurface the tickets when those
come due. And when they resurface it needs to be clear they were exempted previously and shown.
Because endless exemptions/exceptions are not a thing." Jira only, KDEC-017 item 5. Lane L-FX.)

WHAT IT READS (each optional; a path that is ABSENT is "no register there", a path that cannot be
read, parsed or validated is REGISTRATION_UNAVAILABLE -- never "nothing due")

    --central PATH               the central policy register (the kit's policy/policy-registration.json)
    --repository-register PATH   the repository's own .security/policy-registration.json (read it from
                                 the protected default branch: the scheduled workflow checks it out)
    --workflows-dir DIR          the caller's .github/workflows: every job whose `with:` sets a literal
                                 `weakening_expires` (the deploy's KDEC-014 version-gap exception, and
                                 any other weakening record); an expression there is named, not guessed
    --ticket-ledger PATH         the ticket reconciler's ledger (.security/ticket-ledger.json). A secret
                                 exception names ONE finding by its `fp`; the ledger knows which
                                 finding ticket carries that fp, so the resurfacing comment names it --
                                 and the finding ticket names the exception back (KDEC-024, LINK)

WHAT IT LISTS, per exception: kind (secret_exception | policy_decision | weakening_record), where it
lives, its ticket, approver and expiry, EXCEPTION_DUE_SOON (expiring within --days, default 14) or
EXCEPTION_OVERDUE (expired, or an expiry nobody can read), days left, and its FULL HISTORY -- the
renewal count, the cap (numbers.max_exception_renewals, kit default 2; the deploy's own cap is the
stronger of that and 2), the prior tickets and approvers, and whether it is over the cap
(EXCEPTION_RENEWAL_LIMIT). Deterministic JSON (--out) and a human summary (--summary).

WHAT --resurface DOES (through scripts/reconcile_tickets.py's Jira backend; credentials from the
environment only, never printed)
    plan (no --apply)   names what it would do and writes nothing                  PLANNED
    --apply             each ticketed exception: reopen the ticket if it is closed, then comment;
                        an unticketed one: ONE issue, stamped exception-due:<key>, found by that
                        stamp next time and commented instead                      RESURFACED
    no Jira credentials the due list is still emitted                              NOT_CONFIGURED
    another tracker, a refused configuration, or a failed write                    RESURFACE_FAILED
    Every comment says the exception was excepted before (history, count, approvers, expiry) -- or
    that it is a first exception -- and that it is now due.

EXIT  0 nothing due   1 exceptions due or overdue (listed)   2 usage
      3 a register or workflow could not be read (REGISTRATION_UNAVAILABLE)   4 RESURFACE_FAILED
"""
import argparse
import datetime
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exception_history as eh  # noqa: E402

DEFAULT_DAYS = 14
# Every value this file emits is a term in assurance-taxonomy.yaml :: exception_resurfacing.
DUE_SOON = 'EXCEPTION_DUE_SOON'
OVERDUE = 'EXCEPTION_OVERDUE'
UNAVAILABLE = 'REGISTRATION_UNAVAILABLE'
STAMP_PREFIX = 'exception-due:'
# KDEC-022 item 2 (C): the register and the exception's Jira ticket disagree (reported, never gating).
TICKET_MISMATCH = 'EXCEPTION_TICKET_MISMATCH'
JIRA_SETTINGS = ('JIRA_HOST', 'JIRA_EMAIL', 'JIRA_TOKEN', 'JIRA_PROJECT')
OTHER_TRACKER_CREDENTIALS = ('GH_TOKEN', 'GITHUB_TOKEN', 'AZDO_PAT')
KIND_LABEL = {'secret_exception': 'secret exception', 'policy_decision': 'policy decision',
              'weakening_record': 'weakening record (version-gap exception)',
              'known_exploited_exception': 'known-exploited exception'}


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def ticket_key(v):
    """A work-item key <PROJECT>-<digits> with no leading zero, or ''."""
    v = _s(v)
    if eh.parse_renews([{'ticket': v, 'approver': 'x', 'from': '2000-01-01', 'expires': '2000-01-01'}])[0] \
            and not v.rsplit('-', 1)[1].startswith('0'):
        return v
    return ''


# ── reading ───────────────────────────────────────────────────────────────────────────────────

def read_register(path, origin):
    """-> (doc or None, status 'absent'|'readable'|'unreadable', note)."""
    import policy_registration as pr
    if not path:
        return None, 'absent', ''
    if not os.path.exists(path):
        return None, 'absent', 'no %s register at %s' % (origin, path)
    try:
        text = io.open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError) as exc:
        return None, 'unreadable', 'the %s register %s cannot be read: %s' % (origin, path, exc)
    doc, problems = pr.parse_registration(text, origin)
    if problems:
        return None, 'unreadable', 'the %s register %s is refused: %s' % (origin, path, problems[0][1])
    return doc, 'readable', ''


def read_workflows(wdir):
    """-> (list of (file, job, with), notes, unreadable notes)."""
    found, notes, bad = [], [], []
    if not wdir or not os.path.isdir(wdir):
        return found, notes, bad
    try:
        import yaml
    except ImportError:
        # Not reading the caller's workflows is not "no weakening records in them".
        bad.append('PyYAML is unavailable, so the workflows in %s could not be read' % wdir)
        return found, notes, bad
    for name in sorted(os.listdir(wdir)):
        if not name.endswith(('.yml', '.yaml')):
            continue
        path = os.path.join(wdir, name)
        try:
            doc = yaml.safe_load(io.open(path, encoding='utf-8'))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            bad.append('the workflow %s cannot be read: %s' % (name, str(exc).splitlines()[0]))
            continue
        for jname, job in sorted(((doc or {}).get('jobs') or {}).items()) if isinstance(doc, dict) else []:
            w = (job or {}).get('with') if isinstance(job, dict) else None
            if isinstance(w, dict) and 'weakening_expires' in w:
                found.append((name, jname, w))
    return found, notes, bad


# ── the items ─────────────────────────────────────────────────────────────────────────────────

def _item(kind, key, where, origin, entry, ticket, approver, expires, renews, cap, today, days, notes):
    grants, why = eh.parse_renews(renews)
    if grants is None:
        notes.append('%s: its history is unreadable (%s); it cannot be shown to be under the cap' % (key, why))
        hist = {'renewals': None, 'history': 'unreadable', 'prior_tickets': [], 'prior_approvers': [], 'since': ''}
    else:
        hist = eh.summary(grants)
    exp = eh._date(expires)
    if exp is None:
        status, days_left = OVERDUE, None
        notes.append('%s: expiry %r is not a YYYY-MM-DD date; an expiry nobody can read has not "not arrived"'
                     % (key, expires))
    else:
        days_left = (exp - today).days
        if days_left < 0:
            status = OVERDUE
        elif days_left <= days:
            status = DUE_SOON
        else:
            return None
    n = hist['renewals']
    over = n is not None and n > cap
    if over:
        note = ('%s: renewed %d time(s) and the cap is %d -- it can NOT be renewed again; fix the cause'
                % (eh.EXCEPTION_RENEWAL_LIMIT, n, cap))
    elif n is None:
        note = 'history unreadable: refused as unattributed until it is fixed'
    else:
        note = 'within the cap: %d of %d renewal(s) used' % (n, cap)
    return {'key': key, 'kind': kind, 'where': where, 'origin': origin, 'entry': entry, 'ticket': ticket,
            'approver': approver, 'expires': _s(expires) if isinstance(expires, str) else str(expires),
            'status': status, 'days_left': days_left, 'renewals': n, 'cap': cap, 'over_cap': over,
            'history': hist['history'], 'since': hist['since'], 'prior_tickets': hist['prior_tickets'],
            'prior_approvers': hist['prior_approvers'], 'note': note}


def collect(sources, today, days):
    """-> (due items, notes, unreadable notes)."""
    due, notes, bad = [], [], []
    cap = eh.kit_default_max_renewals
    central = sources.get('central')
    if central is not None:
        cap = eh.cap_from_numbers(central.get('numbers'))[0]
    for origin in ('central', 'repository'):
        doc = sources.get(origin)
        for e in (doc or {}).get('policies') or []:
            eid = _s(e.get('id'))
            d = e.get('decision') or {}
            it = _item('policy_decision', 'decision:%s:%s' % (origin, eid), '%s register, entry %s' % (origin, eid),
                       origin, eid, ticket_key(d.get('exception_ref')), _s(d.get('authority')), d.get('expires'),
                       d.get('renews'), cap, today, days, notes)
            if it:
                due.append(it)
            for x in e.get('secret_exceptions') or []:
                fp = _s(x.get('finding'))
                it = _item('secret_exception', 'secret:%s:%s:%s' % (origin, eid, fp),
                           '%s register, entry %s, finding %s' % (origin, eid, fp), origin, eid,
                           ticket_key(x.get('ticket')), _s(x.get('approver')), x.get('expires'), x.get('renews'),
                           cap, today, days, notes)
                if it:
                    it['finding'] = fp
                    due.append(it)
    # The deploy holds the stronger of the authority's cap and the kit default.
    wcap = min(cap, eh.kit_default_max_renewals)
    for fname, job, w in sources.get('workflows') or []:
        key = 'weakening:%s:%s' % (fname, job)
        exp = w.get('weakening_expires')
        if isinstance(exp, str) and '${{' in exp:
            notes.append('%s: weakening_expires is %s, not a literal date -- it cannot be resurfaced from the '
                         'workflow file; record its expiry where this check can read it' % (key, exp))
            continue
        raw = w.get('weakening_renews')
        renews = None
        if isinstance(raw, str) and raw.strip():
            try:
                renews = json.loads(raw)
            except ValueError:
                renews = 'unreadable'
        it = _item('weakening_record', key, 'workflow %s, job %s' % (fname, job), 'workflow', job,
                   ticket_key(w.get('weakening_exception_ref')), _s(w.get('weakening_authority')),
                   exp if isinstance(exp, str) else str(exp), renews, wcap, today, days, notes)
        if it:
            due.append(it)
    due.sort(key=lambda i: (i['expires'], i['key']))
    return due, notes, bad


# ── what the ticket is told ───────────────────────────────────────────────────────────────────

def body(it):
    when = ('expires %s (%d day(s) left)' % (it['expires'], it['days_left']) if it['status'] == DUE_SOON
            else 'expired %s%s' % (it['expires'], '' if it['days_left'] is None
                                   else ' (%d day(s) ago)' % -it['days_left']))
    lines = ['EXCEPTION %s: the %s at %s %s.' % ('DUE' if it['status'] == DUE_SOON else 'OVERDUE',
                                                KIND_LABEL[it['kind']], it['where'], when)]
    if it['renewals']:
        lines.append('This exception was excepted before: %s.' % it['history'])
    elif it['renewals'] == 0:
        lines.append('This is its first exception: it has not been excepted before.')
    else:
        lines.append('Its history cannot be read, so it cannot be shown to be under the renewal cap.')
    if it['renewals'] is not None:
        lines.append('Renewals: %d of %d allowed. Current grant approved by %s%s.'
                     % (it['renewals'], it['cap'], it['approver'] or '(no approver named)',
                        ', ticket %s' % it['ticket'] if it['ticket'] else ''))
    if it['over_cap']:
        lines.append('%s: it is over the renewal cap and can NOT be renewed again -- the finding reverts to '
                     'its normal routing (a secret blocks). Fix the cause.' % eh.EXCEPTION_RENEWAL_LIMIT)
    elif it['renewals'] is not None and it['renewals'] + 1 > it['cap']:
        lines.append('It is now due, and it can NOT be renewed again: it is at the renewal cap (%d). Fix the '
                     'cause before it expires.' % it['cap'])
    else:
        lines.append('It is now due: fix the cause, or renew it on a new ticket with this grant added to '
                     '`renews` (that would be renewal %d of %d).' % ((it['renewals'] or 0) + 1, it['cap']))
    if it.get('finding_tickets'):
        lines.append('The finding this exception covers is tracked on %s (the ticket reconciler\'s '
                     'finding ticket, which names this exception back).'
                     % ', '.join(it['finding_tickets']))
    lines.append('Raised by the scheduled exception check (scripts/exception_due.py, KDEC-018).')
    return '\n'.join(lines)


def title(it):
    t = 'Exception %s: %s, %s' % ('due' if it['status'] == DUE_SOON else 'overdue', KIND_LABEL[it['kind']],
                                  it['where'])
    return t if len(t) <= 240 else t[:237] + '...'


# ── resurfacing ───────────────────────────────────────────────────────────────────────────────

def finding_tickets(ledger_path):
    """-> ({finding fp: [ticket key]}, note). From the reconciler's ledger: each cluster entry
    records the fps of its members and the ticket's human key (KDEC-024). An absent path is no
    cross-reference, said; an unreadable one is named, never read as "no finding ticket"."""
    if not ledger_path:
        return {}, ''
    if not os.path.exists(ledger_path):
        return {}, 'no ticket ledger at %s, so no finding ticket can be named' % ledger_path
    try:
        doc = json.load(io.open(ledger_path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return {}, 'the ticket ledger %s could not be read (%s); no finding ticket is named' % (
            ledger_path, exc)
    clusters = doc.get('clusters') if isinstance(doc, dict) else None
    out = {}
    for entry in (clusters or {}).values():
        if not isinstance(entry, dict) or entry.get('merged_into') or not entry.get('ref'):
            continue
        key = str(entry.get('key') or entry.get('ref'))
        for fp in entry.get('fps') or []:
            out.setdefault(str(fp), [])
            if key not in out[str(fp)]:
                out[str(fp)].append(key)
    return out, ''


def choose(env, factory):
    """-> (backend, state, why). state None means a usable Jira backend."""
    want = _s(env.get('TICKET_BACKEND')).lower()
    if want and want != 'jira':
        return None, 'RESURFACE_FAILED', ('TICKET_BACKEND is %r: the exception check resurfaces on Jira only '
                                          '(KDEC-017 item 5)' % want)
    jira = [k for k in JIRA_SETTINGS if _s(env.get(k))]
    other = [k for k in OTHER_TRACKER_CREDENTIALS if _s(env.get(k))]
    if not jira:
        if other:
            return None, 'RESURFACE_FAILED', ('a non-Jira tracker credential is configured and no Jira one: the '
                                              'exception check resurfaces on Jira only (KDEC-017 item 5)')
        return None, 'NOT_CONFIGURED', ('no Jira credentials are configured (JIRA_HOST, JIRA_EMAIL, JIRA_TOKEN, '
                                        'JIRA_PROJECT): the due list is emitted and nothing is resurfaced')
    if factory is not None:
        backend, why = factory(env)
    else:
        import reconcile_tickets as rt
        clean = dict((k, v) for k, v in env.items() if k not in OTHER_TRACKER_CREDENTIALS)
        clean['TICKET_BACKEND'] = 'jira'
        backend, why = rt.choose_backend(clean)
    if backend is None:
        return None, 'RESURFACE_FAILED', 'the Jira configuration was refused: %s' % _safe(why)
    if getattr(backend, 'name', '') != 'jira':
        return None, 'RESURFACE_FAILED', 'the configured tracker is not Jira: Jira only (KDEC-017 item 5)'
    return backend, None, 'jira backend configured'


def _safe(detail):
    lowered = str(detail).lower()
    for marker in ('authorization', 'bearer ', 'basic ', 'token ', 'password'):
        if marker in lowered:
            return 'detail withheld: it contained something credential-shaped'
    return str(detail)


def resurface(due, env, apply_changes, factory):
    """-> (state, actions, why)."""
    if not due:
        return 'NOTHING_TO_RESURFACE', [], 'nothing is due'
    backend, state, why = choose(env, factory)
    if state:
        return state, [], why
    actions = []
    if not apply_changes:
        for it in due:
            actions.append({'key': it['key'], 'action': ('comment on %s (reopen it if it is closed)' % it['ticket']
                                                          if it['ticket'] else 'create one issue stamped %s%s'
                                                          % (STAMP_PREFIX, it['key'])), 'result': 'planned'})
        return 'PLANNED', actions, 'plan only (apply is off): nothing was written'
    failed = False
    stamps = None
    created = 0
    ceiling = getattr(backend, 'create_ceiling', None)
    for it in due:
        text = body(it)
        ref = it['ticket']
        if not ref:
            stamp = STAMP_PREFIX + it['key']
            if stamps is None:
                smap, complete, sdetail = backend.sweep()
                stamps = smap if complete else None
                if stamps is None:
                    actions.append({'key': it['key'], 'action': 'sweep', 'result': 'failed: %s' % _safe(sdetail)})
                    failed = True
                    stamps = {}
                    continue
            hits = stamps.get(stamp) or []
            if hits:
                ref = str(hits[0].get('key') or hits[0].get('ref'))
            elif ceiling is None or created >= ceiling:
                actions.append({'key': it['key'], 'action': 'create', 'result': 'refused: the creation ceiling '
                                '(TICKET_CREATE_CEILING) is reached or not configured'})
                failed = True
                continue
            else:
                new, detail = backend.create({'cluster_key': stamp, 'members': [], 'subject': ''}, text, title(it))
                if not new:
                    actions.append({'key': it['key'], 'action': 'create', 'result': 'failed: %s' % _safe(detail)})
                    failed = True
                    continue
                created += 1
                stamps[stamp] = [{'ref': new, 'key': new}]
                actions.append({'key': it['key'], 'action': 'create %s' % new, 'result': 'ok'})
                continue
        rec, ok, detail = backend.resolve(ref)
        if not ok:
            actions.append({'key': it['key'], 'action': 'resolve %s' % ref, 'result': 'failed: %s' % _safe(detail)})
            failed = True
            continue
        status = (((rec or {}).get('fields') or {}).get('status') or {}).get('statusCategory') or {}
        if status.get('key') == 'done':
            rok, rwhy = backend.reopen(ref)
            actions.append({'key': it['key'], 'action': 'reopen %s' % ref,
                            'result': 'ok' if rok else 'refused: %s' % _safe(rwhy)})
        cok, cdetail = backend.comment(ref, text)
        actions.append({'key': it['key'], 'action': 'comment %s' % ref,
                        'result': 'ok' if cok else 'failed: %s' % _safe(cdetail)})
        failed = failed or not cok
    if failed:
        return 'RESURFACE_FAILED', actions, 'one or more tickets could not be written (listed)'
    return 'RESURFACED', actions, 'every due exception was raised on its ticket'


# ── the Jira cross-check (KDEC-022 item 2, C) ─────────────────────────────────────────────────

def ticketed(sources):
    """Every exception that names a ticket, due or not: (key, kind, where, ticket, approver, prior tickets)."""
    out = []
    for origin in ('central', 'repository'):
        for e in (sources.get(origin) or {}).get('policies') or []:
            eid = _s(e.get('id'))
            d = e.get('decision') or {}
            grants = eh.parse_renews(d.get('renews'))[0] or []
            if ticket_key(d.get('exception_ref')):
                out.append(('decision:%s:%s' % (origin, eid), 'policy_decision', '%s register, entry %s' % (origin, eid),
                            ticket_key(d.get('exception_ref')), _s(d.get('authority')), [g['ticket'] for g in grants]))
            for kind, field in (('secret_exception', 'secret_exceptions'),
                                ('known_exploited_exception', 'known_exploited_exceptions')):
                for x in e.get(field) or []:
                    fp = _s(x.get('finding'))
                    grants = eh.parse_renews(x.get('renews'))[0] or []
                    if ticket_key(x.get('ticket')):
                        out.append(('%s:%s:%s:%s' % (kind.split('_')[0], origin, eid, fp), kind,
                                    '%s register, entry %s, finding %s' % (origin, eid, fp), ticket_key(x.get('ticket')),
                                    _s(x.get('approver')), [g['ticket'] for g in grants]))
    return out


def cross_check(sources, backend, apply_changes):
    """Hold each exception's Jira ticket to the register: it exists, names the same approver, and its
    links, text or comments show every renewal. -> (mismatches, actions). Never a gate input."""
    mismatches, actions = [], []
    for key, kind, where, ticket, approver, prior in ticketed(sources):
        rec, ok, detail = backend.resolve(ticket)
        reasons = []
        if not ok:
            reasons.append('ticket %s does not exist or cannot be read (%s)' % (ticket, _safe(detail)))
        else:
            blob = json.dumps(rec, sort_keys=True).lower()
            if approver and approver.lower() not in blob:
                reasons.append('the ticket does not name the approver %r the register records' % approver)
            for p in prior:
                if p.lower() not in blob:
                    reasons.append('the ticket does not show the renewal %s (no link, mention or comment)' % p)
        if not reasons:
            continue
        m = {'key': key, 'kind': kind, 'where': where, 'ticket': ticket, 'code': TICKET_MISMATCH, 'reasons': reasons}
        mismatches.append(m)
        if ok and apply_changes:
            text = '%s: the policy register and this ticket disagree about the %s at %s:\n- %s\n' \
                   'Raised by the weekly exception check (scripts/exception_due.py --cross-check, KDEC-022). ' \
                   'The gate does not read this ticket; fix whichever record is wrong.' % (
                       TICKET_MISMATCH, KIND_LABEL.get(kind, kind), where, '\n- '.join(reasons))
            cok, cdetail = backend.comment(ticket, text)
            actions.append({'key': key, 'action': 'comment %s (%s)' % (ticket, TICKET_MISMATCH),
                            'result': 'ok' if cok else 'failed: %s' % _safe(cdetail)})
    return mismatches, actions


# ── output ────────────────────────────────────────────────────────────────────────────────────

def render(doc):
    out = ['### Exceptions coming due (KDEC-018)', '',
           'State **%s** on %s (window %d day(s)); resurfacing **%s**.' % (doc['state'], doc['today'], doc['days'],
                                                                           doc['resurface_state']), '']
    if doc['due']:
        out += ['| status | kind | where | ticket | expires | days | renewals / cap | history |',
                '|---|---|---|---|---|---|---|---|']
        for i in doc['due']:
            out.append('| %s | %s | %s | %s | %s | %s | %s / %s%s | %s |'
                       % (i['status'], i['kind'], i['where'], i['ticket'] or '(none)', i['expires'],
                          '' if i['days_left'] is None else i['days_left'],
                          '?' if i['renewals'] is None else i['renewals'], i['cap'],
                          ' **%s**' % eh.EXCEPTION_RENEWAL_LIMIT if i['over_cap'] else '', i['history']))
        out.append('')
    for n in doc['notes'] + doc['unreadable']:
        out.append('- %s' % n)
    if doc['resurface_why']:
        out.append('- resurfacing: %s' % doc['resurface_why'])
    for a in doc['actions']:
        out.append('- %s: %s -- %s' % (a['key'], a['action'], a['result']))
    xc = doc.get('cross_check') or {}
    if xc.get('state') not in (None, 'NOT_REQUESTED'):
        out += ['', '### Jira cross-check (KDEC-022): %s' % xc['state'], '']
        if xc.get('why'):
            out.append('- %s' % xc['why'])
        for m in xc.get('mismatches') or []:
            out.append('- **%s** %s (ticket %s): %s' % (m['code'], m['where'], m['ticket'], '; '.join(m['reasons'])))
    return '\n'.join(out) + '\n'


def main(argv=None, env=None, backend_factory=None):
    ap = argparse.ArgumentParser(description='List, and resurface, every exception coming due.')
    ap.add_argument('--central', default='')
    ap.add_argument('--repository-register', default='')
    ap.add_argument('--workflows-dir', default='')
    ap.add_argument('--ticket-ledger', default='')
    ap.add_argument('--today', default='')
    ap.add_argument('--days', type=int, default=DEFAULT_DAYS)
    ap.add_argument('--out', default='')
    ap.add_argument('--summary', default='')
    ap.add_argument('--github-output', default='')
    ap.add_argument('--resurface', action='store_true')
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--cross-check', action='store_true',
                    help='hold every ticketed exception to its Jira ticket (KDEC-022 item 2, C); reported only')
    a = ap.parse_args(argv)
    env = os.environ if env is None else env
    if a.days < 0:
        print('--days must be zero or more')
        return 2
    try:
        today = datetime.date.fromisoformat(a.today) if a.today else datetime.date.today()
    except ValueError:
        print('--today %r is not a YYYY-MM-DD date' % a.today)
        return 2
    sources, sources_seen, unreadable = {}, [], []
    for origin, path in (('central', a.central), ('repository', a.repository_register)):
        doc, status, note = read_register(path, origin)
        if path:
            sources_seen.append({'origin': origin, 'path': path, 'status': status})
        if status == 'unreadable':
            unreadable.append(note)
        sources[origin] = doc
    wf, wnotes, wbad = read_workflows(a.workflows_dir)
    if a.workflows_dir:
        sources_seen.append({'origin': 'workflows', 'path': a.workflows_dir,
                             'status': 'unreadable' if wbad else ('readable' if os.path.isdir(a.workflows_dir)
                                                                  else 'absent')})
    unreadable += wbad
    sources['workflows'] = wf
    due, notes, _bad = collect(sources, today, a.days)
    notes = wnotes + notes
    by_fp, lnote = finding_tickets(a.ticket_ledger)
    if lnote:
        notes.append(lnote)
    for it in due:
        if it.get('finding') and by_fp.get(it['finding']):
            it['finding_tickets'] = sorted(by_fp[it['finding']])
    if unreadable:
        state = UNAVAILABLE
    else:
        state = 'EXCEPTIONS_DUE' if due else 'NOTHING_DUE'
    rstate, actions, rwhy = ('NOT_REQUESTED', [], '')
    if a.resurface:
        if unreadable:
            rstate, rwhy = 'NOT_ATTEMPTED', 'a register or workflow could not be read'
        else:
            rstate, actions, rwhy = resurface(due, env, a.apply, backend_factory)
    xc = {'state': 'NOT_REQUESTED', 'why': '', 'mismatches': []}
    if a.cross_check:
        if unreadable:
            xc = {'state': 'NOT_ATTEMPTED', 'why': 'a register or workflow could not be read', 'mismatches': []}
        else:
            backend, bstate, bwhy = choose(env, backend_factory)
            if bstate:
                xc = {'state': bstate, 'why': bwhy, 'mismatches': []}
            else:
                mism, xacts = cross_check(sources, backend, a.apply)
                actions = list(actions) + xacts
                xc = {'state': 'CHECKED', 'why': '%d ticketed exception(s) checked' % len(ticketed(sources)),
                      'mismatches': mism}
    doc = {'schema': 'exception-due/1', 'state': state, 'cross_check': xc, 'today': today.isoformat(), 'days': a.days,
           'sources': sources_seen, 'due': due, 'counts': {'due_soon': sum(1 for i in due if i['status'] == DUE_SOON),
                                                          'overdue': sum(1 for i in due if i['status'] == OVERDUE),
                                                          'over_cap': sum(1 for i in due if i['over_cap'])},
           'notes': notes, 'unreadable': unreadable, 'resurface_state': rstate, 'resurface_why': rwhy,
           'actions': actions}
    text = render(doc)
    if a.out:
        with io.open(a.out, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True) + '\n')
    if a.summary:
        with io.open(a.summary, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text)
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('state=%s\ndue_count=%d\noverdue_count=%d\nover_cap_count=%d\nresurface_state=%s\n'
                     % (state, len(due), doc['counts']['overdue'], doc['counts']['over_cap'], rstate))
            fh.write('cross_check_state=%s\nticket_mismatch_count=%d\n' % (xc['state'], len(xc['mismatches'])))
    print(text)
    if state == UNAVAILABLE:
        return 3
    if rstate == 'RESURFACE_FAILED':
        return 4
    return 1 if (due or xc['mismatches']) else 0


if __name__ == '__main__':
    sys.exit(main())
