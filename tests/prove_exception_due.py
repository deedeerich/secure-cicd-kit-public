#!/usr/bin/env python3
"""Exceptions RESURFACE when they come due, onto their ticket, saying plainly they were excepted
before. (KDEC-018 item 4, owner 2026-10-22: "have a timing mechanism to resurface the tickets when
those come due. And when they resurface it needs to be clear they were exempted previously and
shown." Jira only, KDEC-017 item 5. Lane L-FX.)

WHAT IT PROVES (scripts/exception_due.py; .github/workflows/reusable-exception-due.yml;
templates/exception-due.yml) -- NO REAL JIRA: the Jira backend is a recording fake

    E1  due soon: an exception expiring within N days (default 14) is listed EXCEPTION_DUE_SOON
        with its days left; one beyond N is not; --days widens it
    E2  expired: an exception past its expiry is listed EXCEPTION_OVERDUE; an unreadable expiry is
        overdue too (an expiry nobody can read has not "not arrived")
    E3  every kind is found: register secret exceptions, register decisions (central and the
        repository's own file), and the deploy weakening records (KDEC-014) in the caller's
        workflows -- each with its full history, renewal count and cap
    E4  renewed within the cap shows its history and "within the cap"; over the cap is flagged
        EXCEPTION_RENEWAL_LIMIT
    E5  deterministic JSON (two runs, identical bytes) and a human summary
    E6  nothing due exits 0 with NOTHING_DUE; an UNREADABLE register (or caller workflow) exits 3
        with REGISTRATION_UNAVAILABLE -- never "nothing due"
    E7  no Jira credentials: resurface_state NOT_CONFIGURED, the due list is still emitted (JSON
        and summary), the run is not a failure and not "nothing due"
    E8  with a (fake) Jira: an open ticket gets a comment; a closed ticket is reopened, then
        commented; an unticketed exception gets ONE issue (found by its stamp next time, never
        duplicated); every body says it was excepted before (history, count, approvers, expiry)
        and that it is now due; a failed write is RESURFACE_FAILED (exit 4); plan mode writes nothing
    E9  Jira only: a run configured for another tracker is refused by name
    E10 credentials are never printed: not in stdout, the summary or the JSON
    E11 the reusable workflow: a credential-free list job (contents: read, no environment, no
        secrets), the resurface job in the protected environment, armed only on schedule or
        dispatch on the default branch; data reaches scripts through env:; the template caller
        runs weekly; the list step, run as shipped, fails on an unreadable register and passes
        (with the summary) when exceptions are due

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _deploy_steps as D  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

TODAY = '2026-10-22'
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-exception-due.yml')
TEMPLATE = os.path.join(ROOT, 'templates', 'exception-due.yml')
TOKEN = 'tok-NEVER-PRINT-7f3a9c'
G1 = {'ticket': 'SEC-1200', 'approver': 'Robin Example', 'from': '2026-01-10', 'expires': '2026-04-10'}
G2 = {'ticket': 'SEC-1311', 'approver': 'Dana Example', 'from': '2026-04-10', 'expires': '2026-07-10'}
G3 = {'ticket': 'SEC-1420', 'approver': 'Dana Example', 'from': '2026-07-10', 'expires': '2026-10-10'}


def day(n):
    return (datetime.date.fromisoformat(TODAY) + datetime.timedelta(days=n)).isoformat()


def dec(expires, **over):
    d = {'authority': 'Dana Example', 'reason': 'adoption', 'decided_on': '2026-10-01', 'expires': expires,
         'environment_reviewers': ['platform-approvers']}
    d.update(over)
    return d


def sx(finding, ticket, expires, renews=None):
    item = {'finding': finding, 'ticket': ticket, 'explanation': 'fixture credential; rotation tracked',
            'approver': 'Dana Example', 'expires': expires, 'environment_reviewers': ['platform-approvers']}
    if renews is not None:
        item['renews'] = renews
    return item


def central(policies, **over):
    doc = {'schema_version': 2, 'register_id': 'due',
           'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
           'policies': policies}
    doc.update(over)
    return doc


def fixture_central():
    return central([
        {'id': 'org', 'scope': {'org': 'acme'}, 'rung': 'crawl', 'decision': dec('2099-01-31'),
         'secret_exceptions': [
             sx('a1b2c3d4e5f6', 'SEC-1500', day(5), [G2, G1]),      # due soon, renewed twice (cap 2)
             sx('0f1e2d3c4b5a', 'SEC-1501', day(-3)),               # overdue, first exception
             sx('aaaaaaaaaaaa', 'SEC-1502', day(10), [G1, G2, G3]),  # due soon, over the cap
             sx('bbbbbbbbbbbb', 'SEC-1503', day(20)),               # due only with --days 30
             sx('cccccccccccc', 'SEC-1504', day(200))]},            # not due
        {'id': 'org-prod-da', 'scope': {'org': 'acme', 'environment_tier': 'prod'},
         'deploy_approval': {'self_review_prevented': 'not_required'},
         'decision': dec(day(7), exception_ref='SEC-1600', renews=[G1])},  # decision due soon
    ])


CALLER_WF = """name: deploy
on: {push: {branches: [main]}}
jobs:
  deploy:
    uses: acme/kit/.github/workflows/reusable-deploy-containerapp.yml@0000000000000000000000000000000000000000
    with:
      weakening_authority: "A. Named Person"
      weakening_reason: "no carried scanner reads this target yet"
      weakening_exception_ref: "SEC-1700"
      weakening_expires: "%s"
      weakening_renews: '[{"ticket": "SEC-1650", "approver": "Robin Example", "from": "2026-06-01", "expires": "2026-09-01"}]'
  later:
    uses: acme/kit/.github/workflows/reusable-security.yml@0000000000000000000000000000000000000000
    with:
      weakening_reason: "computed"
      weakening_authority: "Dana Example"
      weakening_expires: ${{ vars.expiry_date }}
""" % day(2)


class FakeJira(object):
    """A recording stand-in for reconcile_tickets.Jira: the same five calls, no network."""
    name = 'jira'
    create_ceiling = 5

    def __init__(self, closed=(), fail_comment=False, stamps=None):
        self.calls, self.closed, self.fail_comment = [], set(closed), fail_comment
        self.stamps = dict(stamps or {})

    def resolve(self, ref):
        self.calls.append(('resolve', ref))
        state = 'done' if ref in self.closed else 'indeterminate'
        return {'key': ref, 'fields': {'status': {'statusCategory': {'key': state}}}}, True, 'resolved'

    def reopen(self, ref):
        self.calls.append(('reopen', ref))
        self.closed.discard(ref)
        return True, 'reopened'

    def comment(self, ref, text):
        self.calls.append(('comment', ref, text))
        return (not self.fail_comment), 'comment status %s' % (500 if self.fail_comment else 201)

    def sweep(self, known_refs=()):
        self.calls.append(('sweep',))
        return dict((k, [{'ref': v, 'key': v, 'state': 'open'}]) for k, v in self.stamps.items()), True, 'swept'

    def create(self, cluster, body, title):
        self.calls.append(('create', cluster.get('cluster_key'), title, body))
        ref = 'NEW-%d' % (len(self.stamps) + 1)
        self.stamps[cluster.get('cluster_key')] = ref
        return ref, 'created %s' % ref


def main():
    try:
        import yaml
        import exception_due as ed
    except ImportError as exc:
        print('FAIL: scripts/exception_due.py cannot be imported (%s): the resurfacing check is not built' % exc)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='exception-due-')
    try:
        def write(rel, text):
            p = os.path.join(work, rel)
            if not os.path.isdir(os.path.dirname(p)):
                os.makedirs(os.path.dirname(p))
            with io.open(p, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
            return p

        cpath = write('kit/policy/policy-registration.json', json.dumps(fixture_central()))
        rpath = write('repo/.security/policy-registration.json', json.dumps({
            'schema_version': 2, 'register_id': 'repo',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
            'policies': [{'id': 'own-prod', 'scope': {'environment_tier': 'prod'}, 'rung': 'crawl',
                          'decision': dec(day(-1), exception_ref='SEC-1800')}]}))
        wdir = os.path.join(work, 'repo', '.github', 'workflows')
        write('repo/.github/workflows/deploy.yml', CALLER_WF)

        def run(extra, env=None, factory=None):
            out = os.path.join(work, 'due-%d.json' % len(os.listdir(work)))
            summ = out + '.md'
            argv = ['--central', cpath, '--repository-register', rpath, '--workflows-dir', wdir,
                    '--today', TODAY, '--out', out, '--summary', summ] + extra
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = ed.main(argv, env=env if env is not None else {}, backend_factory=factory)
            finally:
                sys.stdout = old
            doc = json.load(io.open(out, encoding='utf-8')) if os.path.exists(out) else {}
            text = io.open(out, encoding='utf-8').read() if os.path.exists(out) else ''
            md = io.open(summ, encoding='utf-8').read() if os.path.exists(summ) else ''
            return rc, doc, text, md, buf.getvalue()

        # ---- E1 / E2 / E3 / E4 / E5 -------------------------------------------------------------
        rc, doc, text, md, out = run([])
        due = dict((d.get('key'), d) for d in doc.get('due') or [])
        print('  default run: rc=%d state=%s due=%s' % (rc, doc.get('state'), sorted(due)))
        check(rc == 1 and doc.get('state') == 'EXCEPTIONS_DUE', 'E1: due exceptions did not exit 1 / '
              'EXCEPTIONS_DUE: rc=%d %r' % (rc, doc.get('state')))
        def find(**kv):
            return [d for d in due.values() if all(d.get(k) == v for k, v in kv.items())]
        a = find(kind='secret_exception', ticket='SEC-1500')
        check(a and a[0]['status'] == 'EXCEPTION_DUE_SOON' and a[0]['days_left'] == 5,
              'E1: the exception expiring in 5 days is not EXCEPTION_DUE_SOON: %r' % a)
        check(a and a[0]['renewals'] == 2 and a[0]['cap'] == 2 and not a[0]['over_cap']
              and 'previously excepted 2 time(s) since 2026-01-10' in a[0]['history']
              and a[0]['prior_tickets'] == ['SEC-1200', 'SEC-1311']
              and a[0]['prior_approvers'] == ['Robin Example', 'Dana Example'],
              'E4: the twice-renewed exception does not carry its full history: %r' % a)
        b = find(kind='secret_exception', ticket='SEC-1501')
        check(b and b[0]['status'] == 'EXCEPTION_OVERDUE' and b[0]['history'] == 'first exception',
              'E2: the expired exception is not EXCEPTION_OVERDUE / first exception: %r' % b)
        c = find(kind='secret_exception', ticket='SEC-1502')
        check(c and c[0]['over_cap'] and 'EXCEPTION_RENEWAL_LIMIT' in c[0].get('note', ''),
              'E4: the exception renewed over the cap is not flagged EXCEPTION_RENEWAL_LIMIT: %r' % c)
        check(not find(ticket='SEC-1503') and not find(ticket='SEC-1504'),
              'E1: an exception beyond 14 days was listed')
        d = find(kind='policy_decision', entry='org-prod-da')
        check(d and d[0]['status'] == 'EXCEPTION_DUE_SOON' and d[0]['ticket'] == 'SEC-1600' and d[0]['renewals'] == 1,
              'E3: the central softening decision due in 7 days is not listed with its ticket and history: %r' % d)
        r = find(kind='policy_decision', entry='own-prod')
        check(r and r[0]['status'] == 'EXCEPTION_OVERDUE' and r[0]['origin'] == 'repository',
              'E3: the repository file\'s expired decision is not listed: %r' % r)
        w = find(kind='weakening_record')
        check(len(w) == 1 and w[0]['ticket'] == 'SEC-1700' and w[0]['status'] == 'EXCEPTION_DUE_SOON'
              and w[0]['renewals'] == 1 and 'SEC-1650' in w[0]['history'],
              'E3: the deploy weakening record (KDEC-014) in the caller workflow is not listed with its '
              'history: %r' % w)
        check(any('not a literal date' in n for n in doc.get('notes') or []),
              'E3: a weakening_expires that is an expression is not named as unresurfaceable: %r' % doc.get('notes'))
        check(not find(kind='policy_decision', entry='org'), 'E1: the decision expiring in 2099 was listed')
        rc2, _d2, text2, _m2, _o2 = run([])
        check(text == text2 and text.strip(), 'E5: two runs on the same input wrote different JSON')
        check('EXCEPTION_OVERDUE' in md and 'previously excepted 2 time(s)' in md and 'first exception' in md,
              'E5: the human summary does not list the due exceptions with their history')
        rc, doc, _t, _m, _o = run(['--days', '30'])
        check(any(x.get('ticket') == 'SEC-1503' for x in doc.get('due') or []), 'E1: --days 30 did not list +20')
        bad_expiry = central([{'id': 'x', 'scope': {'org': 'acme'}, 'rung': 'crawl', 'decision': dec('2099-01-31'),
                               'secret_exceptions': [sx('dddddddddddd', 'SEC-1900', 'someday')]}])
        rc_b, doc_b, _t, _m, _o = (None, None, None, None, None)
        p2 = write('kit2/policy-registration.json', json.dumps(bad_expiry))
        rc_b = ed.main(['--central', p2, '--today', TODAY, '--out', p2 + '.json'], env={})
        doc_b = json.load(io.open(p2 + '.json', encoding='utf-8')) if os.path.exists(p2 + '.json') else {}
        check(any(x.get('ticket') == 'SEC-1900' and x.get('status') == 'EXCEPTION_OVERDUE' for x in doc_b.get('due') or []),
              'E2: an unreadable expiry was not treated as overdue: rc=%r %r' % (rc_b, doc_b.get('due')))

        # ---- E6 -------------------------------------------------------------------------------------
        none_due = write('kit3/policy-registration.json', json.dumps(central([
            {'id': 'org', 'scope': {'org': 'acme'}, 'rung': 'crawl', 'decision': dec('2099-01-31')}])))
        rc = ed.main(['--central', none_due, '--today', TODAY, '--out', none_due + '.json'], env={})
        nd = json.load(io.open(none_due + '.json', encoding='utf-8')) if os.path.exists(none_due + '.json') else {}
        check(rc == 0 and nd.get('state') == 'NOTHING_DUE', 'E6: nothing due did not exit 0 / NOTHING_DUE: %r %r'
              % (rc, nd.get('state')))
        broken = write('kit4/policy-registration.json', '{broken')
        rc = ed.main(['--central', broken, '--today', TODAY, '--out', broken + '.json'], env={})
        bd = json.load(io.open(broken + '.json', encoding='utf-8')) if os.path.exists(broken + '.json') else {}
        check(rc == 3 and bd.get('state') == 'REGISTRATION_UNAVAILABLE' and not bd.get('due'),
              'E6: an unreadable register did not exit 3 / REGISTRATION_UNAVAILABLE: rc=%r %r' % (rc, bd.get('state')))
        bad_wf = write('repo-badwf/.github/workflows/x.yml', 'jobs: [unclosed\n')
        rc = ed.main(['--workflows-dir', os.path.dirname(bad_wf), '--today', TODAY,
                      '--out', bad_wf + '.json'], env={})
        check(rc == 3, 'E6: an unparseable caller workflow did not exit 3: %r' % rc)

        # ---- E7 no credentials ---------------------------------------------------------------------
        rc, doc, _t, md, out = run(['--resurface', '--apply'], env={})
        check(rc == 1 and doc.get('resurface_state') == 'NOT_CONFIGURED' and doc.get('due'),
              'E7: with no Jira credentials the run is not NOT_CONFIGURED with the due list kept: rc=%d %r'
              % (rc, doc.get('resurface_state')))
        check('NOT_CONFIGURED' in md and 'SEC-1500' in md, 'E7: the summary does not say NOT_CONFIGURED beside the list')

        # ---- E8 a fake Jira ------------------------------------------------------------------------
        env = {'TICKET_BACKEND': 'jira', 'JIRA_HOST': 'https://jira.example.invalid', 'JIRA_EMAIL': 'bot@example.invalid',
               'JIRA_TOKEN': TOKEN, 'JIRA_PROJECT': 'SEC'}
        fake = FakeJira(closed={'SEC-1501'})
        rc, doc, text, md, out = run(['--resurface', '--apply'], env=env, factory=lambda e: (fake, 'fake jira'))
        print('  fake jira: rc=%d resurface=%s calls=%d' % (rc, doc.get('resurface_state'), len(fake.calls)))
        check(doc.get('resurface_state') == 'RESURFACED' and rc == 1,
              'E8: the resurfacing did not report RESURFACED: rc=%d %r' % (rc, doc.get('resurface_state')))
        comments = dict((c[1], c[2]) for c in fake.calls if c[0] == 'comment')
        body = comments.get('SEC-1500', '')
        for must in ('excepted before', 'previously excepted 2 time(s) since 2026-01-10', 'SEC-1200', 'SEC-1311',
                     'Robin Example', 'Dana Example', day(5), 'now due', '2 of 2'):
            check(must in body, 'E8: the comment on SEC-1500 does not state %r:\n%s' % (must, body))
        check('first exception' in comments.get('SEC-1501', ''), 'E8: the first exception\'s comment does not say so')
        check(('reopen', 'SEC-1501') in fake.calls and fake.calls.index(('reopen', 'SEC-1501')) <
              [i for i, c in enumerate(fake.calls) if c[0] == 'comment' and c[1] == 'SEC-1501'][0],
              'E8: the closed ticket SEC-1501 was not reopened before the comment: %r' % fake.calls)
        check(('reopen', 'SEC-1500') not in fake.calls, 'E8: an open ticket was reopened')
        check('EXCEPTION_RENEWAL_LIMIT' in comments.get('SEC-1502', ''), 'E8: the over-cap comment does not say so')
        # An unticketed exception: one issue, then found by its stamp.
        unt = central([{'id': 'org', 'scope': {'org': 'acme'}, 'rung': 'walk',
                        'decision': dec(day(3), environment_reviewers=['platform-approvers'])}])
        up = write('kit5/policy-registration.json', json.dumps(unt))
        fake2 = FakeJira()
        ed.main(['--central', up, '--today', TODAY, '--out', up + '.json', '--resurface', '--apply'], env=env,
                backend_factory=lambda e: (fake2, 'fake'))
        creates = [c for c in fake2.calls if c[0] == 'create']
        check(len(creates) == 1 and 'excepted' in creates[0][3], 'E8: an unticketed exception did not get ONE issue: %r'
              % creates)
        ed.main(['--central', up, '--today', TODAY, '--out', up + '.json', '--resurface', '--apply'], env=env,
                backend_factory=lambda e: (fake2, 'fake'))
        creates = [c for c in fake2.calls if c[0] == 'create']
        check(len(creates) == 1 and any(c[0] == 'comment' and c[1] == 'NEW-1' for c in fake2.calls),
              'E8: a second run created a duplicate instead of commenting on the stamped issue: %r' % fake2.calls)
        # A failed write is RESURFACE_FAILED.
        fake3 = FakeJira(fail_comment=True)
        rc, doc, _t, _m, _o = run(['--resurface', '--apply'], env=env, factory=lambda e: (fake3, 'fake'))
        check(rc == 4 and doc.get('resurface_state') == 'RESURFACE_FAILED',
              'E8: a failed comment did not exit 4 / RESURFACE_FAILED: rc=%d %r' % (rc, doc.get('resurface_state')))
        # Plan mode writes nothing.
        fake4 = FakeJira(closed={'SEC-1501'})
        rc, doc, _t, _m, _o = run(['--resurface'], env=env, factory=lambda e: (fake4, 'fake'))
        check(not [c for c in fake4.calls if c[0] in ('comment', 'reopen', 'create')] and doc.get('resurface_state') == 'PLANNED',
              'E8: plan mode wrote to the tracker: %r %r' % (fake4.calls, doc.get('resurface_state')))

        # ---- E9 Jira only --------------------------------------------------------------------------
        gh_env = {'TICKET_BACKEND': 'github', 'GH_TOKEN': TOKEN, 'TICKET_REPO': 'acme/x', 'TICKET_STAMP_LABEL': 'kit'}
        rc, doc, _t, _m, out = run(['--resurface', '--apply'], env=gh_env)
        check(rc == 4 and doc.get('resurface_state') == 'RESURFACE_FAILED' and 'Jira only' in json.dumps(doc),
              'E9: a non-Jira tracker was not refused by name: rc=%d %r' % (rc, doc.get('resurface_state')))

        # ---- E10 never print a credential ----------------------------------------------------------
        for name, (rc_, doc_, text_, md_, out_) in (
                ('fake', run(['--resurface', '--apply'], env=env, factory=lambda e: (FakeJira(), 'fake'))),
                ('github', run(['--resurface', '--apply'], env=gh_env))):
            check(TOKEN not in text_ + md_ + out_, 'E10: the credential appears in the %s run\'s output' % name)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # ---- E11 the workflow and the template ---------------------------------------------------------
    if not os.path.isfile(WF) or not os.path.isfile(TEMPLATE):
        fails.append('E11: %s or %s does not exist' % (os.path.relpath(WF, ROOT), os.path.relpath(TEMPLATE, ROOT)))
    else:
        wf = yaml.safe_load(io.open(WF, encoding='utf-8'))
        jobs = wf.get('jobs') or {}
        lst, res = jobs.get('list') or {}, jobs.get('resurface') or {}
        check(lst and res, 'E11: the workflow has no list and resurface jobs: %r' % sorted(jobs))
        check('environment' not in lst and 'secrets.' not in json.dumps(lst)
              and (lst.get('permissions') or {}) == {'contents': 'read'},
              'E11: the list job holds a credential or more than contents: read')
        check('environment' in res and 'secrets.JIRA_TOKEN' in json.dumps(res),
              'E11: the resurface job does not take the Jira credential from the protected environment')
        cond = str(res.get('if', ''))
        for must in ('schedule', 'workflow_dispatch', 'default_branch'):
            check(must in cond, 'E11: the resurface job is not armed only on schedule/dispatch on the default '
                  'branch (if: %s)' % cond)
        for jn, j in jobs.items():
            for s in j.get('steps') or []:
                if '${{' in (s.get('run') or ''):
                    fails.append('E11: job %s step %r interpolates an expression into run: (data must arrive '
                                 'through env:)' % (jn, s.get('name')))
        on = wf.get('on', wf.get(True)) or {}
        sec = ((on.get('workflow_call') or {}).get('secrets') or {})
        check(set(sec) == {'JIRA_EMAIL', 'JIRA_TOKEN'}, 'E11: the workflow takes secrets other than Jira\'s: %r' % sorted(sec))
        tpl = yaml.safe_load(io.open(TEMPLATE, encoding='utf-8'))
        ton = tpl.get('on', tpl.get(True)) or {}
        crons = [c.get('cron', '') for c in ton.get('schedule') or []]
        check(crons and all(len(c.split()) == 5 and c.split()[4] not in ('*',) for c in crons),
              'E11: the template caller has no weekly schedule: %r' % crons)
        check('reusable-exception-due.yml@' in json.dumps(tpl), 'E11: the template does not call the reusable')
        # The list step, run as shipped.
        step = next((s for s in lst.get('steps') or [] if s.get('id') == 'list'), None)
        bash, why = pbf.usable_bash()
        if step is None:
            fails.append('E11: the list job has no step id: list')
        elif not bash:
            print('  note: no usable bash (%s); the list step was not run' % why)
        else:
            for case, text, want_rc in (('unreadable', '{broken', 1),
                                        ('due', json.dumps(fixture_central()), 0)):
                ws = tempfile.mkdtemp(prefix='due-step-')
                try:
                    os.makedirs(os.path.join(ws, '.kit', 'scripts'))
                    for f in ('exception_due.py', 'exception_history.py', 'policy_registration.py', 'rung_ladder.py',
                              'enforcement_axes.py', 'ticket_reference.py', 'reconcile_tickets.py',
                              'ticket_routing.py'):
                        shutil.copy(os.path.join(ROOT, 'scripts', f), os.path.join(ws, '.kit', 'scripts', f))
                    os.makedirs(os.path.join(ws, '.kit', 'policy'))
                    with io.open(os.path.join(ws, '.kit', 'policy', 'policy-registration.json'), 'w') as fh:
                        fh.write(text)
                    values = {'inputs.central_register_path': 'policy/policy-registration.json',
                              'inputs.repository_register_path': '.security/policy-registration.json',
                              'inputs.workflows_dir': '.github/workflows', 'inputs.days': '14',
                              'github.workspace': ws.replace('\\', '/'), 'runner.temp': ws.replace('\\', '/')}
                    env, _u = pbf.resolve_env(step.get('env'), values)
                    env['TODAY_OVERRIDE'] = TODAY
                    rc, outs, log, summ = D.run_script(bash, step.get('run') or '', env, cwd=ws)
                    print('  list step %-10s exit=%d state=%s due=%s' % (case, rc, outs.get('state'), outs.get('due_count')))
                    if (rc == 0) != (want_rc == 0):
                        fails.append('E11: the list step, %s register, exited %d\n%s' % (case, rc, log[-500:]))
                    if case == 'unreadable' and outs.get('state') != 'REGISTRATION_UNAVAILABLE':
                        fails.append('E11: the list step did not name REGISTRATION_UNAVAILABLE: %r' % outs)
                    if case == 'due' and (outs.get('due_count') in ('', '0', None) or 'SEC-1500' not in summ):
                        fails.append('E11: the list step did not report the due exceptions in its summary: %r' % outs)
                finally:
                    shutil.rmtree(ws, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: every exception coming due (default 14 days) or expired -- register secret exceptions, register '
          'decisions, the deploy\'s version-gap weakening records -- is listed with its full history, count and cap, '
          'deterministically; an unreadable register is never "nothing due"; with no Jira credentials the list is '
          'still emitted (NOT_CONFIGURED); through a (fake) Jira each ticket is commented, reopened when closed, or '
          'created once when there is none, saying plainly it was excepted before and is now due; Jira only; '
          'no credential is printed; the reusable workflow lists without a credential and resurfaces only on a '
          'schedule or dispatch on the default branch, from the protected environment.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
