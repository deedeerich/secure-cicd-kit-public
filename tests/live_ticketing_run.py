#!/usr/bin/env python3
"""TICKETING_BACKENDS.md R-1 and R-2, against the OWNER'S PERSONAL Jira or Azure DevOps. Run by a
person, with a transcript. Never against a consumer's tracker; never in CI.

WHAT IT DOES

    R-1  live REFUSALS. The configuration is broken one value at a time -- wrong host, bad token,
         missing project, missing stamp field, missing reopen transition (Jira) or state (Azure
         DevOps) -- and each must be refused BY NAME. The transition is tried on the calibration
         ticket (reads only), since Jira offers transitions per issue, not at run start.
         Every write is BLOCKED in this phase by the runner itself, so a refusal that failed to
         happen cannot write anything.
    R-2  live BEHAVIOUR on real tickets, with a ledger kept beside the transcript:
           T-1  two runs over the same synthetic finding: the second creates nothing
           T-2  a narrowed membership: nothing new
           T-02 before the "joined" run the RUNNER, standing in for a person, writes a note
                before and after the machine-owned block; after it, both notes must still be
                there with the block updated between them (completion ledger row T-02)
         and, after a PERSON acts on the ticket the run printed (the bridge has no delete and no
         way to duplicate or close by itself -- by design):
           T-6  a person duplicates the ticket with the stamp     -> BINDING_AMBIGUOUS
           T-7  a person closes it with nothing backing it        -> reopened
           T-8  a person makes the reopen refusable               -> successor, predecessor kept
         Cleanup is by a person: the bridge cannot delete, and the transcript lists every ticket.
    R-3  the LIFECYCLE (KDEC-024) on ONE synthetic ticket: NEW, SLA escalation (comment, priority,
         label), closure on a verified clearance, RECURRED reopen, and closure again -- so the
         ticket ends closed. The reference date is advanced per step instead of waiting.
    R-4  KDEC-037, the TRACKER half of ticket templates (Jira only): a ticket the runner files by hand
         (no stamp) is surfaced as a CANDIDATE, a person's link decision labels it, the next submission
         finds it EXACT, a new finding is created through the reconciler, extended once and closed by a
         reviewer-verified closure, and the tracker intake reads the manual ticket back. The GitHub half
         (the review record and its pull request approval) is the LOCAL stand-in: no GitHub host is
         contacted, and no review here is a real person's concurrence. (Version 2 since 2026-11-04: a
         link decision records a CLOSED DUPLICATE under the manual ticket.)
    R-5  KDEC-037 version 2 (the owner's rulings, 2026-11-04), on Jira OR GitHub Issues: a finding is
         CREATED with its trust and confidence on the ticket; the same finding from another tool with
         new evidence is a CLOSED DUPLICATE (a sub-task / issue closed under the original) and the
         original says what it added; a ticket the runner files by hand naming another finding's asset
         and identifier makes that finding a POSSIBLE DUPLICATE, created in triage, then merged by a
         person's triage; a search the RUNNER withholds for one call creates the ticket DEDUPE PENDING
         and the next submission re-runs it; the fixer's resolve is PENDING VERIFICATION, then a
         verifier who is not the fixer closes it.
    INTAKE  read only (every write blocked by the runner): the search-first intake adapter pages
         through every ticket of the project (Azure DevOps, Jira or GitHub Issues).

SAFETY

    * It refuses to start unless EVERY required variable for the chosen backend is present
      (scripts/check_env.py's list), naming each missing one.
    * It refuses to touch the network without --confirm-live.
    * Only the chosen backend's values are passed to the bridge, so a .env holding both trackers
      is not refused as two backends (C-2) and the other credential is never in reach.
    * The transcript never contains a credential: every value of a *TOKEN*, *PAT*, *EMAIL* or
      *PASSWORD* variable is replaced before anything is printed or written.
    * The synthetic findings carry a per-run marker, so its tickets are recognisable for cleanup.

USAGE
    python tests/live_ticketing_run.py --backend jira --env-file .env --confirm-live --phase r1
    python tests/live_ticketing_run.py --backend azdo --env-file .env --confirm-live --phase r2
    python tests/live_ticketing_run.py --backend jira --env-file .env --confirm-live \
        --phase r2-after-human --run-dir <dir printed by the r2 run>
    GH_TOKEN=... TICKET_REPO=owner/repo TICKET_STAMP_LABEL=secure-cicd-kit TICKET_CALIBRATION_REF=<n> \
        python tests/live_ticketing_run.py --backend github --env-file .env --confirm-live --phase r5
      (github values may come from the process environment: a token is never written to a file)

EXIT  0 every check held   1 a check failed   2 refused to start (missing value, no
      --confirm-live, misuse)
"""
import argparse
import io
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

SECRET_MARKERS = ('TOKEN', 'PAT', 'EMAIL', 'PASSWORD', 'SECRET')
SHARED = ('TICKET_BACKEND', 'TICKET_STAMP_LABEL', 'TICKET_CREATE_CEILING', 'TICKET_RETRY_CEILING',
          'TICKET_INSTANCE_THRESHOLD', 'TICKET_DEGRADED_RUN_THRESHOLD')
PREFIX = {'jira': 'JIRA_', 'azdo': 'AZDO_', 'github': 'GH_'}
GITHUB_KEYS = ('GH_TOKEN', 'TICKET_REPO', 'TICKET_STAMP_LABEL', 'TICKET_CALIBRATION_REF')


class Transcript(object):
    def __init__(self, path, secrets):
        self.path = path
        self.secrets = sorted((s for s in secrets if s), key=len, reverse=True)
        self.lines = []

    def clean(self, text):
        text = str(text)
        for s in self.secrets:
            text = text.replace(s, '<redacted>')
        return text

    def say(self, text=''):
        line = self.clean(text)
        self.lines.append(line)
        print(line)

    def save(self):
        io.open(self.path, 'w', encoding='utf-8').write('\n'.join(self.lines) + '\n')


class WriteBlocker(object):
    """Wraps urlopen. In R-1 every non-read request is refused BEFORE it leaves the machine."""

    def __init__(self, inner):
        self.inner = inner
        self.block_writes = False
        self.blocked = []
        self.calls = 0

    def __call__(self, req, *a, **kw):
        self.calls += 1
        method = req.get_method()
        reads = method == 'GET' or (method == 'POST' and any(
            p in req.full_url for p in ('/search/jql', '/_apis/wit/wiql', '/workitemsbatch')))
        if self.block_writes and not reads:
            self.blocked.append('%s %s' % (method, req.full_url))
            raise urllib.error.URLError('R-1 write blocked by the runner')
        return self.inner(req, *a, **kw)


def backend_env(values, backend):
    env = dict((k, v) for k, v in values.items()
               if k.startswith(PREFIX[backend]) or k in SHARED or (backend == 'github' and k in GITHUB_KEYS))
    if backend == 'azdo' and not env.get('AZDO_ORG_URL') and values.get('AZDO_ORG'):
        env['AZDO_ORG_URL'] = values['AZDO_ORG']
    env['TICKET_BACKEND'] = backend
    return env


def synthetic(marker, members):
    import reconcile_tickets as rt
    recs = {'a': rt._rec('kit-live-test', 'LIVE-%s' % marker, 'live/%s/a.txt' % marker,
                         'live-%s-a' % marker, aliases=['live-%s' % marker, 'live-%s-b' % marker],
                         severity='low'),
            'b': rt._rec('kit-live-test-2', 'LIVE-%s-B' % marker, 'live/%s/a.txt' % marker,
                         'live-%s-b' % marker, aliases=['live-%s-b' % marker, 'live-%s' % marker],
                         severity='low')}
    return [recs[m] for m in members]


def r1(rt, env, backend, tr, blocker):
    """Each broken value is refused BY NAME, with writes blocked."""
    blocker.block_writes = True
    breaks = {
        'jira': [('JIRA_HOST', 'https://kit-r1-wrong-host.invalid', 'JIRA_HOST'),
                 ('JIRA_TOKEN', 'r1-not-a-token', 'JIRA_TOKEN'),
                 ('JIRA_PROJECT', 'ZZR1NOPE', 'JIRA_PROJECT'),
                 ('JIRA_STAMP_FIELD', 'customfield_1', 'JIRA_STAMP_FIELD'),
                 # T-24: the FIFTH break. Jira's transitions are per issue and per status, so a
                 # missing reopen transition cannot be established at run start; it is exercised
                 # on the calibration ticket, reads only, with every write blocked.
                 ('JIRA_TRANSITION_REOPEN', 'kit-r1-no-such-transition',
                  'JIRA_TRANSITION_REOPEN')],
        'azdo': [('AZDO_ORG_URL', 'https://dev.azure.com/kit-r1-no-such-org', 'AZDO_ORG_URL'),
                 ('AZDO_PAT', 'r1-not-a-pat', 'AZDO_PAT'),
                 ('AZDO_PROJECT', 'zz-r1-nope', 'AZDO_PROJECT'),
                 ('AZDO_STAMP_FIELD', 'Custom.KitR1NoSuchField', 'AZDO_STAMP_FIELD'),
                 # T-24: the fifth break. Azure DevOps states are per type, so run start refuses.
                 ('AZDO_STATE_REOPEN', 'kit-r1-no-such-state', 'AZDO_STATE_REOPEN')],
    }[backend]
    ok = True
    for var, bad, named in breaks:
        e = dict(env, **{var: bad})
        b, note = rt.choose_backend(e)
        if b is None:
            refused, detail = True, note
        else:
            good, detail = b.validate()
            refused = not good
            if good and var == 'JIRA_TRANSITION_REOPEN':
                # The shape is fine; the reopen is what must refuse, by name, and write nothing.
                cal = (e.get('JIRA_CALIBRATION_ISSUE') or '').strip()
                reopened, detail = b.reopen(cal) if cal else (
                    False, 'JIRA_CALIBRATION_ISSUE is unset, so the reopen could not be tried')
                refused = not reopened
        by_name = named in detail
        tr.say('R-1  %-18s broken -> %s %s' % (var, 'REFUSED' if refused else 'ACCEPTED',
                                                 '(named)' if by_name else '(NOT named)'))
        tr.say('       %s' % detail)
        ok = ok and refused and by_name
    tr.say('R-1  writes attempted and blocked by the runner: %d' % len(blocker.blocked))
    blocker.block_writes = False
    return ok and not blocker.blocked


HUMAN_BEFORE = 'Human note BEFORE the block (kit live test %s): must survive every kit update.'
HUMAN_AFTER = 'Human note AFTER the block (kit live test %s): must survive every kit update.'


def add_human_text(rt, b, ref, marker):
    """T-02 live: the RUNNER, standing in for a person and saying so in the transcript, writes a
    note before and after the machine-owned block. -> (ok, detail). The bridge never does this;
    it is the fixture the next run's members-added update must not erase."""
    desc, ok, detail = b.read_description(ref)
    if not ok:
        return False, 'could not read ticket %s to add the human note: %s' % (ref, detail)
    before, after = HUMAN_BEFORE % marker, HUMAN_AFTER % marker
    if b.name == 'jira':
        para = lambda t: {'type': 'paragraph', 'content': [{'type': 'text', 'text': t}]}  # noqa
        doc = dict(desc or {'type': 'doc', 'version': 1})
        doc['content'] = [para(before)] + list(doc.get('content') or []) + [para(after)]
        new = doc
    else:
        new = dict(desc or {}, html='<p>%s</p>%s<p>%s</p>' % (before, (desc or {}).get(
            'html') or '', after))
    good, detail = b.write_description(ref, new, desc)
    return good, detail


def human_text_held(rt, b, ref, marker, joined_identity):
    """-> (held, detail): both human notes still there, and the joined member in the block."""
    desc, ok, detail = b.read_description(ref)
    if not ok:
        return False, 'could not read ticket %s back: %s' % (ref, detail)
    text = b.description_text(desc)
    lines = [ln.strip() for ln in text.split('\n')]
    missing = [w for w, t in (('before', HUMAN_BEFORE % marker), ('after', HUMAN_AFTER % marker))
               if t not in lines]
    if missing:
        return False, 'the human note(s) %s were ERASED by the kit update' % ', '.join(missing)
    if joined_identity not in text:
        return False, 'the joined member %s is not in the block' % joined_identity
    # The block's first and last lines both name the machine-owned block.
    edges = [n for n, ln in enumerate(lines) if 'machine-owned block' in ln]
    if not edges or lines.index(HUMAN_BEFORE % marker) > edges[0] or \
            lines.index(HUMAN_AFTER % marker) < edges[-1]:
        return False, 'the human notes are no longer before and after the block'
    return True, 'both human notes intact, the block updated between them'


def r2(rt, env, tr, run_dir):
    marker = time.strftime('%Y%m%d%H%M%S')
    ledger_path = os.path.join(run_dir, 'ledger.json')
    io.open(os.path.join(run_dir, 'marker'), 'w').write(marker)
    ledger = {}
    ok = True
    counts = []
    for label, members in (('T-1 run 1', 'a'), ('T-1 run 2', 'a'), ('T-2 joined', 'ab'),
                           ('T-2 narrowed', 'b')):
        b, note = rt.choose_backend(env)
        if b is None:
            tr.say('R-2 refused: %s' % note)
            return False
        ref = next((e.get('ref') for e in ledger.values() if e.get('ref')), None)
        if label == 'T-2 joined':
            # T-02: human text around the block BEFORE the members-added update.
            good, detail = add_human_text(rt, b, ref, marker) if ref else (False, 'no ticket')
            tr.say('R-2  T-02 setup   the runner, standing in for a person, wrote a note before '
                   'and after the block of ticket %s: %s' % (ref, detail))
            ok = ok and good
        res = rt.reconcile(*rt.build_clusters(synthetic(marker, members)), backend=b,
                           ledger=ledger, apply_changes=True, today=time.strftime('%Y-%m-%d'))
        made = [c for c in res['created'] if c.get('ref')]
        counts.append(len(made))
        tr.say('R-2  %-14s created %d, outcomes %s, claim %s, calls %s, throttles %d'
               % (label, len(made), json.dumps(res['outcomes'], sort_keys=True),
                  (res.get('ticketing_claim') or {}).get('routing_result'), res.get('calls'),
                  len(res.get('throttles') or [])))
        for c in made:
            tr.say('       ticket %s  (cleanup by a person: the bridge has no delete)' % c['ref'])
        if label in ('T-2 joined', 'T-2 narrowed') and ref:
            # After the join (a members-added write) AND after the narrowing (a T-13 write that
            # marks the departed member POTENTIALLY_ABSENT), the person's notes are intact.
            held, detail = human_text_held(rt, b, ref, marker, 'live-%s-b' % marker)
            tr.say('R-2  T-02 check   %s after %s: %s' % ('HELD' if held else 'FAILED', label,
                                                         detail))
            ok = ok and held
    rt.save_ledger(ledger_path, ledger)
    if counts != [1, 0, 0, 0]:
        tr.say('R-2  FAIL: creations per run %r, expected [1, 0, 0, 0] (T-1, T-2)' % counts)
        ok = False
    ref = next((e.get('ref') for e in ledger.values() if e.get('ref')), None)
    tr.say('')
    tr.say('NEXT, BY A PERSON, on ticket %s, then rerun with --phase r2-after-human --run-dir %s:'
           % (ref, run_dir))
    tr.say('  T-6  duplicate it WITH its stamp (or set the stamp on another ticket)')
    tr.say('  T-7  or: close it with nothing backing it -> the rerun must reopen it')
    tr.say('  T-8  or: close it where no reopen transition/state is permitted -> successor')
    return ok


def r2_after_human(rt, env, tr, run_dir):
    marker = io.open(os.path.join(run_dir, 'marker')).read().strip()
    ledger_path = os.path.join(run_dir, 'ledger.json')
    ledger, note = rt.load_ledger(ledger_path)
    if not ledger:
        tr.say('no ledger at %s: run --phase r2 first' % ledger_path)
        return False
    b, note = rt.choose_backend(env)
    if b is None:
        tr.say('refused: %s' % note)
        return False
    res = rt.reconcile(*rt.build_clusters(synthetic(marker, 'b')), backend=b, ledger=ledger,
                       apply_changes=True, today=time.strftime('%Y-%m-%d'))
    rt.save_ledger(ledger_path, ledger)
    tr.say('R-2  after the human act: outcomes %s' % json.dumps(res['outcomes'], sort_keys=True))
    tr.say('     ambiguous candidates: %s' % [d.get('candidates') for d in res['needs_decision']])
    tr.say('     reopened: %s' % res.get('reopened'))
    tr.say('     successors: %s' % res.get('successors'))
    tr.say('     A PERSON records which of T-6 / T-7 / T-8 this exercised and whether it held.')
    return bool(res['outcomes'].get(rt.BINDING_AMBIGUOUS) or res.get('reopened')
                or res.get('successors'))


def r3(rt, env, tr, run_dir):
    """KDEC-024 live: the LIFECYCLE on ONE synthetic ticket, which ends CLOSED.

        create (NEW) -> SLA overdue: comment, priority one step, label -> verified clearance:
        closed with the run cited -> the finding returns: reopened RECURRED -> cleared again:
        closed. The reference date is advanced by the runner (it is an input to every run), so
        the SLA breach is reached without waiting; the period is 0 days for a LOW finding."""
    import datetime
    marker = time.strftime('%Y%m%d%H%M%S')
    io.open(os.path.join(run_dir, 'marker'), 'w').write(marker)
    rec = dict(synthetic(marker, 'a')[0], job='deps-scan', fp='')
    scanner = rec['scanner']
    coverage = {scanner: {'scanner': scanner, 'job': 'deps-scan', 'established': True,
                          'gate': 'PASS', 'execution': 'COMPLETE', 'scope': ''}}
    day0 = datetime.date.today()
    numbers = {'sla_period_days': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}}
    ledger, ok = {}, True
    steps = (('create (NEW)', [rec], 0, 'created'),
             ('SLA overdue -> escalate', [rec], 1, 'escalations'),
             ('verified clearance -> close', [], 2, 'cleared'),
             ('the finding returns -> RECURRED', [rec], 3, 'reopened'),
             ('cleared again -> close (cleanup)', [], 4, 'cleared'))
    for label, recs, offset, key in steps:
        b, note = rt.choose_backend(env)
        if b is None:
            tr.say('R-3 refused: %s' % note)
            return False
        today = (day0 + datetime.timedelta(days=offset)).isoformat()
        ctx = {'run_url': 'live-r3 %s step %d' % (marker, offset), 'commit': '%040d' % offset,
               'coverage': coverage, 'numbers': numbers}
        res = rt.reconcile(*rt.build_clusters(recs), backend=b, ledger=ledger,
                           apply_changes=True, today=today, context=ctx)
        got = [x for x in res.get(key) or [] if x.get('ref') and not x.get('planned')]
        if key == 'reopened':
            # Reopened in place, or -- where the workflow refuses the reopen -- a successor that
            # references the predecessor (TC 4.2). Either is the recurrence, named RECURRED.
            got = [x for x in got + list(res.get('successors') or [])
                   if x.get('classification') == 'RECURRED']
        if key == 'cleared':
            got = [x for x in got if x.get('closed')]
        if key == 'escalations':
            got = [x for x in got if x.get('marked') and x.get('commented')]
        held = bool(got)
        ok = ok and held
        tr.say('R-3  %-34s %s  state %s, claim %s, calls %s, %s' % (
            label, 'HELD' if held else 'FAILED', res.get('ticketing_state'),
            (res.get('ticketing_claim') or {}).get('routing_result'), res.get('calls'),
            json.dumps([dict((k, v) for k, v in x.items() if k in ('ref', 'classification',
                                                                    'applied', 'closed'))
                        for x in got], sort_keys=True)[:300]))
        for n in res.get('notes') or []:
            if 'failed' in n or 'could not' in n or 'incomplete' in n:
                tr.say('       note: %s' % n)
    rt.save_ledger(os.path.join(run_dir, 'ledger.json'), ledger)
    for e in ledger.values():
        tr.say('R-3  ticket %s (%s) -- created and closed by this run; the bridge has no delete'
               % (e.get('key'), e.get('ref')))
    return ok


def _await_search(rt, env, tr, text, ck_label, want_ref, seconds=120):
    """Jira's enhanced search is eventually consistent: wait (bounded) until `want_ref` is found."""
    import ticket_intake as ti
    deadline = time.time() + seconds
    while True:
        b, _n = rt.choose_backend(env)
        b.set_routing(None, '', [])
        tickets, state, _d = ti.JiraIntake(b).search_all(text=text, ck_label=ck_label)
        if any(t['ref'] == str(want_ref) for t in tickets):
            return True
        if time.time() > deadline:
            tr.say('       the search did not show ticket %s within %d s (state %s)' % (want_ref, seconds, state))
            return False
        time.sleep(10)


def r4(rt, env, tr, run_dir):
    """KDEC-037 live, the TRACKER half: templates, dedupe against a MANUAL ticket, a confirmed link, an exact
    re-find, a created ticket, an extension and a reviewer-verified closure, and the tracker intake -- on the
    owner's PERSONAL Jira. The GitHub half (the review record and the approval of its pull request) is the
    local GitHub stand-in: no GitHub host is contacted, and no review here is a real person's concurrence."""
    import kit_api as ka
    import kit_api_server as ks
    import prove_kit_api_server as ps
    import ticket_templates as tt
    marker = time.strftime('%Y%m%d%H%M%S')
    io.open(os.path.join(run_dir, 'marker'), 'w').write(marker)
    ident = 'LIVE-R4-%s' % marker
    rid = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/kit-live/providers/' \
          'Microsoft.Storage/storageAccounts/live%s' % marker
    f = tt.example_finding(identifier=ident, title='kit live r4 %s storage allows TLS 1.0' % marker,
                           asset=dict(tt.example_finding()['asset'], resource_id=rid))
    ok = True
    b, note = rt.choose_backend(env)
    if b is None:
        tr.say('R-4 refused: %s' % note)
        return False
    good, detail = b.validate()
    if not good:
        tr.say('R-4 refused at run start: %s' % detail)
        return False
    # A PERSON'S TICKET: made by the runner, standing in for a person, with no stamp and no kit label.
    doc, status, err = b._req('POST', '/rest/api/3/issue', {'fields': {
        'project': {'key': env['JIRA_PROJECT']}, 'summary': 'kit live r4 %s TLS 1.0 still on' % marker,
        'issuetype': {'name': b.type_cluster},
        'description': rt.adf_from_text('Filed by hand (kit live test r4): %s allows TLS 1.0 (%s).' % (rid, ident))}})
    manual = str((doc or {}).get('id') or '')
    tr.say('R-4  the runner, standing in for a person, filed ticket %s (%s) with no stamp: %s'
           % (manual, (doc or {}).get('key'), err or status))
    if not manual:
        return False
    ok = _await_search(rt, env, tr, ident, '', manual) and ok
    w = ps.World(ka, env, run_dir, [])
    w.env.update({'KIT_API_OPERATIONS': w.env['KIT_API_OPERATIONS'] + ',tickets.submit',
                  'KIT_API_TODAY': time.strftime('%Y-%m-%d'), 'KIT_API_REVIEWS_DIR': os.path.join(run_dir, 'reviews')})
    os.makedirs(w.env['KIT_API_REVIEWS_DIR'], exist_ok=True)
    io.open(os.path.join(w.env['KIT_API_REVIEWS_DIR'], 'approvers.json'), 'w', encoding='utf-8').write(
        json.dumps({'approver_lists': {'review-concurrence': ['live-r4-reviewer']}}))
    n = [0]

    def submit(params, dry=False):
        n[0] += 1
        review = 'LIVE-R4-%s-%02d' % (marker, n[0])
        p = dict(params, review_id=review)
        rec = {'schema': 'kit-review-record/2', 'review_id': review, 'status': 'FINALIZED', 'decision': 'AGREE',
               'submitted_by': 'tines-kit-app[bot]', 'concurred_by': 'live-r4-reviewer',
               'concurred_on': time.strftime('%Y-%m-%d'), 'evidence_set_sha256': tt.evidence_set_sha256(p),
               'statement': 'live r4: a stand-in concurrence (local GitHub stand-in)'}
        io.open(os.path.join(w.env['KIT_API_REVIEWS_DIR'], '%s.json' % review), 'w', encoding='utf-8').write(
            json.dumps(rec))
        w.stub.merge_review_record('.security/reviews/%s.json' % review, '%040x' % (900 + n[0]), 900 + n[0],
                                   'tines-kit-app[bot]', ['live-r4-reviewer'])
        res, _seen, _i = w.call(ks, 'tickets.submit', p, key='live-r4-%s-%02d' % (marker, n[0]), dry_run=dry)
        return res

    def items(res):
        return (res.get('data') or {}).get('items') or []

    base = {'template': 'finding', 'template_version': 2, 'items': [f]}
    ck = tt.normalize('finding', f, {})['correlation_key']
    res = submit(base, dry=True)
    it = (items(res) or [{}])[0]
    held = manual in [c['ref'] for c in it.get('candidates') or []]
    tr.say('R-4  dry run: the manual ticket is a CANDIDATE, nothing written: %s  (%s)'
           % ('HELD' if held else 'FAILED', json.dumps(it, sort_keys=True)[:300]))
    ok = ok and held
    res = submit(dict(base, link_decisions=[{'correlation_key': ck, 'decision': 'link', 'ref': manual}]))
    it = (items(res) or [{}])[0]
    labels, _o, _d = rt.choose_backend(env)[0].labels_of(manual)
    held = it.get('outcome') == tt.TEMPLATE_CLOSED_DUPLICATE and ('secure-cicd-kit-ck-%s' % ck) in labels
    tr.say('R-4  a person\'s link decision: a closed duplicate under the manual ticket, which is labelled: %s  (labels %s)'
           % ('HELD' if held else 'FAILED', labels))
    ok = ok and held
    ok = _await_search(rt, env, tr, ident, 'secure-cicd-kit-ck-%s' % ck, manual) and ok
    res = submit(base)
    it = (items(res) or [{}])[0]
    held = it.get('outcome') == tt.TEMPLATE_LINKED_EXACT and it.get('ref') == manual
    tr.say('R-4  the next submission finds it EXACT: %s  (%s, basis %s)' % ('HELD' if held else 'FAILED',
                                                                              it.get('outcome'), it.get('basis')))
    ok = ok and held
    g = tt.example_finding(identifier=ident + '-NEW', title='kit live r4 %s a second finding' % marker,
                           asset=dict(tt.example_finding()['asset'], resource_id=rid + '-b'))
    res = submit({'template': 'finding', 'template_version': 2, 'items': [g]})
    it = (items(res) or [{}])[0]
    created = it.get('ref')
    held = it.get('outcome') == tt.TEMPLATE_TICKET_CREATED and bool(created)
    tr.say('R-4  a finding no ticket tracks is CREATED through the reconciler: %s  (ticket %s %s)'
           % ('HELD' if held else 'FAILED', created, it.get('key')))
    ok = ok and held
    if created:
        exp = time.strftime('%Y-%m-%d', time.localtime(time.time() + 30 * 86400))
        res = submit({'template': 'extension', 'template_version': 2, 'items': [{
            'ref': created, 'new_expiry': exp, 'reason': 'kit live r4: the vendor moved the date by a month',
            'extensions_used': 0, 'requested_by': 'app-team', 'evidence': f['evidence'], 'waiting_on': 'fix'}]})
        labels, _o, _d = rt.choose_backend(env)[0].labels_of(created)
        held = res.get('api_state') == 'API_COMPLETED' and 'secure-cicd-kit-extension-1' in labels
        tr.say('R-4  extension 1 of 2 recorded on the ticket: %s' % ('HELD' if held else 'FAILED'))
        ok = ok and held
        res = submit({'template': 'closure', 'template_version': 2, 'items': [{
            'ref': created, 'action': 'verify', 'requested_by': 'app-team', 'fixed_by': 'dev-one',
            'evidence': f['evidence'],
            'verification': {'kind': 'reviewer'}}]})
        held = res.get('api_state') == 'API_COMPLETED' and (items(res) or [{}])[0].get('outcome') == \
            tt.TEMPLATE_TICKET_CLOSED
        tr.say('R-4  reviewer-verified closure closed it: %s  (%s)' % ('HELD' if held else 'FAILED',
                                                                     res.get('notes')[-2:]))
        ok = ok and held
    res, _s, _i = w.call(ks, 'tickets.search', {'tracker_query': {'jql': 'text ~ "\\"%s\\""' % ident,
                                                                 'max_results': 10}})
    got = [t['ref'] for t in (res.get('data') or {}).get('tickets') or []]
    held = res.get('api_state') == 'API_COMPLETED' and manual in got
    tr.say('R-4  tracker intake reads the manual ticket back with its link: %s  (%s)' % (
        'HELD' if held else 'FAILED', got))
    ok = ok and held
    tr.say('R-4  tickets for a PERSON to clean up (the bridge has no delete): %s %s'
           % (manual, created or ''))
    return ok


def _file_manual(b, env, summary, text):
    """The RUNNER, standing in for a person, files a ticket with no stamp and no kit label."""
    import reconcile_tickets as rt
    if b.name == 'github':
        doc, status, err = b._req('POST', '/repos/%s/issues' % b.repo, {'title': summary, 'body': text})
        return str((doc or {}).get('number') or ''), (doc or {}).get('number'), err or status
    if b.name == 'azdo':
        ref, detail = b._create(b.type_cluster, summary, [], text, None)
        return ref or '', ref, detail
    doc, status, err = b._req('POST', '/rest/api/3/issue', {'fields': {
        'project': {'key': env['JIRA_PROJECT']}, 'summary': summary, 'issuetype': {'name': b.type_cluster},
        'description': rt.adf_from_text(text)}})
    return str((doc or {}).get('id') or ''), (doc or {}).get('key'), err or status


def _await_any(rt, env, tr, text, want_ref, seconds=120):
    """Search is eventually consistent (Jira, the GitHub search API): wait, bounded, for `want_ref`."""
    import ticket_intake as ti
    deadline = time.time() + seconds
    while True:
        b, _n = rt.choose_backend(env)
        if hasattr(b, 'set_routing'):
            b.set_routing(None, '', [])
        tickets, state, _d = ti.adapter_for(b).search_all(text=text)
        if any(str(t['ref']) == str(want_ref) for t in tickets):
            return True
        if time.time() > deadline:
            tr.say('       the search did not show ticket %s within %d s (state %s)' % (want_ref, seconds, state))
            return False
        time.sleep(10)


def _status(b, ref):
    if b.name == 'github':
        doc, _s, _e = b._req('GET', '/repos/%s/issues/%s' % (b.repo, ref))
        return (doc or {}).get('state') or ''
    if b.name == 'azdo':
        doc, _s, _e = b._req('GET', '/_apis/wit/workitems/%s?fields=System.State' % ref)
        st = ((doc or {}).get('fields') or {}).get('System.State') or ''
        return 'done' if st == b.state_done else st
    doc, _s, _e = b._req('GET', '/rest/api/3/issue/%s?fields=status' % ref)
    return ((((doc or {}).get('fields') or {}).get('status') or {}).get('statusCategory') or {}).get('key') or ''


def _body(b, ref):
    desc, ok, _d = b.read_description(ref)
    return b.description_text(desc) if ok else ''


def r5(rt, env, tr, run_dir, backend):
    """KDEC-037 version 2 on the owner's PERSONAL tracker (Jira project or a GitHub test repository)."""
    import kit_api as ka
    import kit_api_server as ks
    import prove_kit_api_server as ps
    import ticket_intake as ti
    import ticket_templates as tt
    marker = time.strftime('%Y%m%d%H%M%S')
    io.open(os.path.join(run_dir, 'marker'), 'w').write(marker)
    ident = 'LIVE-R5-%s' % marker
    rid = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/kit-live/providers/' \
          'Microsoft.Storage/storageAccounts/r5%s' % marker
    asset = dict(tt.example_finding()['asset'], resource_id=rid)
    ok = True
    b, note = rt.choose_backend(env)
    if b is None:
        tr.say('R-5 refused: %s' % note)
        return False
    good, detail = b.validate() if hasattr(b, 'validate') else b.probe()
    if not good:
        tr.say('R-5 refused at run start: %s' % detail)
        return False
    stamp = getattr(b, 'stamp_label', '') or 'secure-cicd-kit'
    w = ps.World(ka, env, run_dir, [])
    w.env.update({'KIT_API_OPERATIONS': w.env['KIT_API_OPERATIONS'] + ',tickets.submit',
                  'KIT_API_TODAY': time.strftime('%Y-%m-%d'), 'KIT_API_REVIEWS_DIR': os.path.join(run_dir, 'reviews'),
                  'TICKET_BACKEND': backend})
    if backend == 'github':
        w.env['KIT_API_GH_TICKET_TOKEN'] = env['GH_TOKEN']
        # The kit API's own GitHub calls go to the local stand-in; the TRACKER is the real GitHub
        # Issues of the personal test repository (a runner-only split: in a workflow both are the run host).
        orig = ks.tracker_env
        ks.tracker_env = lambda e: dict(orig(e), GITHUB_API_URL='https://api.github.com')
    os.makedirs(w.env['KIT_API_REVIEWS_DIR'], exist_ok=True)
    io.open(os.path.join(w.env['KIT_API_REVIEWS_DIR'], 'approvers.json'), 'w', encoding='utf-8').write(
        json.dumps({'approver_lists': {'review-concurrence': ['live-r5-reviewer']}}))
    n = [0]
    made = []

    def submit(params, review=True):
        n[0] += 1
        p = dict(params)
        if review:
            rid_ = 'LIVE-R5-%s-%02d' % (marker, n[0])
            p['review_id'] = rid_
            rec = {'schema': 'kit-review-record/2', 'review_id': rid_, 'status': 'FINALIZED', 'decision': 'AGREE',
                   'submitted_by': 'tines-kit-app[bot]', 'concurred_by': 'live-r5-reviewer',
                   'concurred_on': time.strftime('%Y-%m-%d'), 'evidence_set_sha256': tt.evidence_set_sha256(p),
                   'statement': 'live r5: a stand-in concurrence (local GitHub stand-in)'}
            io.open(os.path.join(w.env['KIT_API_REVIEWS_DIR'], '%s.json' % rid_), 'w', encoding='utf-8').write(
                json.dumps(rec))
            w.stub.merge_review_record('.security/reviews/%s.json' % rid_, '%040x' % (950 + n[0]), 950 + n[0],
                                       'tines-kit-app[bot]', ['live-r5-reviewer'])
        res, _seen, _i = w.call(ks, 'tickets.submit', p, key='live-r5-%s-%02d' % (marker, n[0]))
        for i in (res.get('data') or {}).get('items') or []:
            for r_ in (i.get('ref'), i.get('duplicate_ref')):
                if r_ and r_ not in made:
                    made.append(r_)
        return res

    def first(res):
        return (((res.get('data') or {}).get('items')) or [{}])[0]

    def say(label, held, extra):
        tr.say('R-5  %s: %s  (%s)' % (label, 'HELD' if held else 'FAILED', extra))
        return held

    def fresh():
        return rt.choose_backend(env)[0]

    # 1. CREATED, with trust and confidence on the ticket and in the answer.
    f = tt.example_finding(identifier=ident, title='kit live r5 %s storage allows TLS 1.0' % marker, asset=asset,
                           source_tool='defender')
    res = submit({'template': 'finding', 'template_version': 2, 'items': [f]})
    it = first(res)
    orig_ref = it.get('ref')
    body = _body(fresh(), orig_ref) if orig_ref else ''
    ok = say('a finding is CREATED with trust and confidence on the ticket and in the answer',
             it.get('outcome') == tt.TEMPLATE_TICKET_CREATED and isinstance(it.get('trust'), int) and
             isinstance(it.get('confidence'), int) and '| trust score |' in body and '| confidence score |' in body,
             'ticket %s, trust %s [%s], confidence %s' % (orig_ref, it.get('trust'), it.get('trust_basis'),
                                                        it.get('confidence'))) and ok
    if not orig_ref:
        return False
    # 2. EXACT: the same finding from another tool, new evidence, a severity change -> a closed duplicate.
    deadline = time.time() + 120
    while time.time() < deadline:
        smap, _c, _d = fresh().sweep()
        if any(str(h.get('ref')) == str(orig_ref) for hits in smap.values() for h in hits):
            break
        time.sleep(10)
    g = dict(f, source_tool='prowler', source_type='usr', severity='critical',
             evidence={'ref': 'usr/live-r5/2', 'sha256': '7' * 64})
    res = submit({'template': 'finding', 'template_version': 2, 'items': [g]})
    it = first(res)
    ok = say('the same finding from another tool is a CLOSED DUPLICATE under the original',
             it.get('outcome') == tt.TEMPLATE_CLOSED_DUPLICATE and it.get('original_ref') == orig_ref,
             'outcome %s, original %s, duplicate record %s' % (it.get('outcome'), it.get('original_ref'),
                                                               it.get('duplicate_ref'))) and ok
    # 3. NEAR: a person's ticket names the asset and identifier of a NEW finding -> created, flagged, triage.
    ident2 = ident + '-NEAR'
    manual, mkey, mstat = _file_manual(fresh(), env, 'kit live r5 %s TLS on r5b' % marker,
                                       'Filed by hand (kit live r5): %s-b allows TLS 1.0 (%s).' % (rid, ident2))
    tr.say('R-5  the runner, standing in for a person, filed ticket %s (%s) with no stamp: %s' % (manual, mkey, mstat))
    if manual:
        made.append(manual)
        ok = _await_any(rt, env, tr, ident2, manual) and ok
    h = tt.example_finding(identifier=ident2, title='kit live r5 %s near' % marker,
                           asset=dict(asset, resource_id=rid + '-b'))
    res = submit({'template': 'finding', 'template_version': 2, 'items': [h]})
    it = first(res)
    pd = it.get('ref')
    labels = fresh().labels_of(pd)[0] if pd else []
    ok = say('a near match is CREATED, flagged possible-duplicate and put in triage',
             it.get('outcome') == tt.TEMPLATE_POSSIBLE_DUPLICATE and '%s-possible-duplicate' % stamp in labels and
             '%s-triage' % stamp in labels, 'ticket %s, labels %s, candidates %s' % (
                 pd, labels, [c.get('ref') for c in it.get('candidates') or []])) and ok
    if pd and manual:
        res = submit({'template': 'triage', 'template_version': 2, 'items': [
            {'ref': pd, 'original_ref': manual, 'decision': 'merge', 'triaged_by': 'live-r5-triager',
             'reason': 'kit live r5: the hand-filed ticket is the same storage account and rule'}]})
        it = first(res)
        ok = say('a person\'s triage MERGE closes it as a duplicate of the hand-filed ticket',
                 it.get('outcome') == tt.TEMPLATE_CLOSED_DUPLICATE and _status(fresh(), pd) in ('done', 'closed'),
                 'outcome %s, status %s' % (it.get('outcome'), _status(fresh(), pd))) and ok
    # 4. PENDING: the runner withholds the search for ONE call -> created in triage, dedupe-pending.
    real = ti.adapter_for
    ti.adapter_for = lambda bk, name='': ti.NotConfigured('withheld', 'the live runner withheld the search for '
                                                                     'this one call (R-5 pending dedupe)')
    try:
        k = tt.example_finding(identifier=ident + '-PEND', title='kit live r5 %s pending' % marker,
                               asset=dict(asset, resource_id=rid + '-c'))
        res = submit({'template': 'finding', 'template_version': 2, 'items': [k]})
    finally:
        ti.adapter_for = real
    it = first(res)
    pend = it.get('ref')
    labels = fresh().labels_of(pend)[0] if pend else []
    ok = say('a search that did not complete still CREATES the ticket, dedupe-pending, in triage',
             it.get('outcome') == tt.TEMPLATE_DEDUPE_PENDING and '%s-dedupe-pending' % stamp in labels,
             'ticket %s, labels %s' % (pend, labels)) and ok
    # The stamp sweep is a listing that can lag a just-created ticket (GitHub's label listing, Jira's search):
    # the pending pass runs on the next run THAT SEES IT. Wait, bounded, so this run's next submission does.
    deadline = time.time() + 120
    while pend and time.time() < deadline:
        smap, _c, _d = fresh().sweep()
        if any(str(h.get('ref')) == str(pend) for hits in smap.values() for h in hits):
            break
        time.sleep(10)
    m = tt.example_finding(identifier=ident + '-NEXT', title='kit live r5 %s next' % marker,
                           asset=dict(asset, resource_id=rid + '-d'))
    res = submit({'template': 'finding', 'template_version': 2, 'items': [m]})
    labels = fresh().labels_of(pend)[0] if pend else []
    ok = say('the next submission re-runs the pending dedupe',
             '%s-dedupe-done' % stamp in labels and bool((res.get('data') or {}).get('dedupe_rechecked')),
             'labels %s, rechecked %s' % (labels, (res.get('data') or {}).get('dedupe_rechecked'))) and ok
    # 5. CLOSURE: the fixer resolves (pending), then a verifier who is not the fixer closes it.
    ev = {'ref': 'pull/live-r5', 'sha256': 'd' * 64}
    res = submit({'template': 'closure', 'template_version': 2, 'items': [{
        'ref': orig_ref, 'action': 'resolve', 'requested_by': 'live-r5-fixer', 'fixed_by': 'live-r5-fixer',
        'evidence': ev, 'verification': {'kind': 'reviewer'}}]}, review=False)
    it = first(res)
    labels = fresh().labels_of(orig_ref)[0]
    ok = say('the fixer\'s resolve is PENDING VERIFICATION and the approvers are notified',
             it.get('outcome') == tt.TEMPLATE_PENDING_VERIFICATION and '%s-pending-verification' % stamp in labels
             and _status(fresh(), orig_ref) not in ('done', 'closed') and
             bool((res.get('data') or {}).get('notifications')),
             'labels %s, notifications %s' % (labels, (res.get('data') or {}).get('notifications'))) and ok
    res = submit({'template': 'closure', 'template_version': 2, 'items': [{
        'ref': orig_ref, 'action': 'verify', 'requested_by': 'live-r5-fixer', 'fixed_by': 'live-r5-fixer',
        'evidence': ev, 'verification': {'kind': 'reviewer'}}]})
    it = first(res)
    st = _status(fresh(), orig_ref)
    ok = say('a verifier who is not the fixer CLOSES it (Closed-Verified)',
             it.get('outcome') == tt.TEMPLATE_TICKET_CLOSED and st in ('done', 'closed'),
             'outcome %s, status %s, verified by %s' % (it.get('outcome'), st, it.get('verified_by'))) and ok
    if backend == 'github':
        ks.tracker_env = orig
    tr.say('R-5  tickets for a PERSON to clean up (the bridge has no delete): %s' % ', '.join(str(x) for x in made))
    io.open(os.path.join(run_dir, 'cleanup.json'), 'w', encoding='utf-8').write(json.dumps(made))
    return ok


def intake_only(rt, env, tr, blocker):
    """READ ONLY: every write is blocked by the runner. The search-first adapter pages through the project."""
    import ticket_intake as ti
    blocker.block_writes = True
    b, note = rt.choose_backend(env)
    if b is None and env.get('TICKET_BACKEND') == 'azdo' and not env.get('AZDO_STAMP_FIELD'):
        # READ ONLY needs no stamp field: the backend refuses to be built without one (it would write), so the
        # runner builds the reader directly; with no stamp field every work item reads as unstamped.
        b = rt.AzureDevOps(env.get('AZDO_ORG_URL') or env.get('AZDO_ORG'), env['AZDO_PROJECT'], env['AZDO_PAT'], '')
        tr.say('INTAKE  no AZDO_STAMP_FIELD: read only, every work item reads as unstamped (%s)' % note[:80])
    if b is None:
        tr.say('INTAKE refused: %s' % note)
        return False
    if hasattr(b, 'set_routing'):
        b.set_routing(None, '', [])
    ad = ti.adapter_for(b)
    tickets, state, detail = ad.search_all(page_size=50)
    manual = sum(1 for x in tickets if not x.get('stamp'))
    tr.say('INTAKE  %s adapter: %s -- %s; %d ticket(s), %d with no kit stamp' % (
        getattr(ad, 'name', '?'), state, detail, len(tickets), manual))
    for x in tickets[:5]:
        tr.say('        %s %s [%s] %s' % (x.get('key'), x.get('state'), ','.join(x.get('labels') or []),
                                         str(x.get('summary'))[:60]))
    tr.say('INTAKE  writes attempted and blocked: %d' % len(blocker.blocked))
    return state == ti.TRACKER_INTAKE_COMPLETE and not blocker.blocked


def main(argv=None):
    ap = argparse.ArgumentParser(description='Live R-1/R-2/R-3 against a PERSONAL tracker.')
    ap.add_argument('--backend', choices=['jira', 'azdo', 'github'], required=True)
    ap.add_argument('--env-file', default=os.path.join(ROOT, '.env'))
    ap.add_argument('--phase', choices=['r1', 'r2', 'r2-after-human', 'r3', 'r4', 'r5', 'intake'], default='r1')
    ap.add_argument('--run-dir', default='')
    ap.add_argument('--confirm-live', action='store_true',
                    help='required: this contacts the tracker the .env names')
    args = ap.parse_args(argv)

    import check_env
    if not os.path.exists(args.env_file):
        print('REFUSED: no env file at %s' % args.env_file)
        return 2
    values = check_env.load(args.env_file)
    if args.backend == 'github':
        # A GitHub token comes from the process environment (e.g. the gh CLI), never from a file here.
        values = dict(values, **dict((k, os.environ[k]) for k in GITHUB_KEYS if os.environ.get(k)))
        for k in [k for k in values if k.startswith(('JIRA_', 'AZDO_'))]:
            values.pop(k)
    alias = check_env.ALIASES
    need = check_env.REQUIRED[args.backend]
    if args.phase == 'intake':
        # Read only: the connection is all an intake needs (no stamp field, epic or calibration).
        need = dict((k, v) for k, v in need.items() if k in (
            'AZDO_ORG_URL', 'AZDO_PROJECT', 'AZDO_PAT', 'JIRA_HOST', 'JIRA_EMAIL', 'JIRA_TOKEN', 'JIRA_PROJECT',
            'GH_TOKEN', 'TICKET_REPO', 'TICKET_STAMP_LABEL'))
    missing = [k for k in need if not (values.get(k) or values.get(alias.get(k, '')))]
    if missing:
        print('REFUSED: required for %s and missing: %s' % (args.backend, ', '.join(missing)))
        return 2
    if not args.confirm_live:
        print('REFUSED: --confirm-live not given. This contacts the tracker the env file names; '
              'say so explicitly.')
        return 2

    import reconcile_tickets as rt
    env = backend_env(values, args.backend)
    secrets = [v for k, v in values.items() if any(m in k for m in SECRET_MARKERS)]
    run_dir = args.run_dir or tempfile.mkdtemp(prefix='kit-live-%s-' % args.backend)
    tr = Transcript(os.path.join(run_dir, 'transcript-%s-%s.txt'
                                 % (args.phase, time.strftime('%Y%m%dT%H%M%S'))), secrets)
    blocker = WriteBlocker(urllib.request.urlopen)
    urllib.request.urlopen = blocker
    try:
        tr.say('live ticketing run: backend %s, phase %s, %s' % (args.backend, args.phase,
                                                                time.strftime('%Y-%m-%dT%H:%M:%S')))
        tr.say('effective configuration (credentials redacted):')
        for k in sorted(env):
            tr.say('  %-26s %s' % (k, env[k]))
        if args.phase == 'r1':
            ok = r1(rt, env, args.backend, tr, blocker)
        elif args.phase == 'r2':
            ok = r2(rt, env, tr, run_dir)
        elif args.phase == 'r3':
            ok = r3(rt, env, tr, run_dir)
        elif args.phase == 'r5':
            ok = r5(rt, env, tr, run_dir, args.backend)
        elif args.phase == 'intake':
            ok = intake_only(rt, env, tr, blocker)
        elif args.phase == 'r4':
            if args.backend != 'jira':
                tr.say('R-4 is Jira only: the tracker intake adapter is Jira (KDEC-017 item 5; KDEC-037 O-37h)')
                ok = False
            else:
                ok = r4(rt, env, tr, run_dir)
        else:
            ok = r2_after_human(rt, env, tr, run_dir)
        tr.say('RESULT: %s' % ('HELD' if ok else 'FAILED'))
        tr.say('transcript: %s' % tr.path)
    finally:
        urllib.request.urlopen = blocker.inner
        tr.save()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
