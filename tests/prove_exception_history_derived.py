#!/usr/bin/env python3
"""An exception's renewal history comes from GIT, not from what the register says about itself; a
weekly check holds each ticket in Jira to the same story. (KDEC-022 item 2, owner 2026-10-23: option
D, "B plus C".)

WHY THIS EXISTS

    Until KDEC-022 the renewal count was the length of the `renews` list the register declared
    (KDEC-018 item 4). Whoever edits the register can shorten that list -- erase the history -- and
    an exception renewed five times reads as a first grant, under every cap. The owner chose D:
    (B) derive the history from the git history of the protected register file, refuse a register
    whose declared history is shorter than git shows, and cap the DERIVED count; (C) cross-check
    each exception's ticket in Jira weekly, reported and never a gate input.

WHAT IT PROVES (scripts/exception_history.py, scripts/policy_registration.py, scripts/exception_due.py,
.github/actions/resolve-policy) -- against throwaway git repositories, no network

    H1  renewals added over several commits: the resolver walks the register's git history on the
        default branch and derives every grant (ticket, expiry, approver); the exception is in force
        with renewals=2 and its history names the prior tickets
    H2  history ERASED -- the declared `renews` shorter than git shows (all of it, or one grant) --
        is EXCEPTION_HISTORY_TAMPERED: the exception is refused and the resolution routes BLOCKED
    H3  the cap (numbers.max_exception_renewals, kit default 2) applies to the DERIVED count
    H4  a SHALLOW clone cannot show the history: EXCEPTION_HISTORY_UNVERIFIED, the exception refused
        (as unattributed history is today) -- never read as zero renewals
    H5  the fetch the workflow makes (a blob-less partial clone of the default branch: every commit,
        only the register's blobs) DOES show it -- VERIFIED, renewals=2; the cost is measured
    H6  a central SOFTENING decision whose expiry was renewed in git with no `renews` declared is
        EXCEPTION_HISTORY_TAMPERED (BLOCKED) and the softening does not apply
    H7  a central register that is not in any git history: its exceptions are
        EXCEPTION_HISTORY_UNVERIFIED (refused), never trusted on their own say-so
    H8  the pure resolver handed no history at all treats every exception as UNVERIFIED
    H9  (C) exception_due.py --cross-check against the fake Jira of tests/prove_exception_due.py:
        a ticket that exists, names the approver and shows each renewal passes; a missing ticket,
        a different approver, or a renewal the ticket does not show is EXCEPTION_TICKET_MISMATCH --
        in the JSON, the run summary and (with --apply) a comment on the ticket
    H10 the gate never depends on Jira: the resolver neither imports the tracker client nor reads
        a Jira setting; the resolve-policy action fetches the default branch blob-less, not depth 1
    H11 EXCEPTION_HISTORY_TAMPERED, EXCEPTION_HISTORY_UNVERIFIED and EXCEPTION_TICKET_MISMATCH are
        registered taxonomy terms

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
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

TODAY = '2026-10-23'
REPOSITORY = 'acme/ledger-api'
REG = '.security/policy-registration.json'
FP = 'a1b2c3d4e5f6'
TAMPERED = 'EXCEPTION_HISTORY_TAMPERED'
UNVERIFIED = 'EXCEPTION_HISTORY_UNVERIFIED'
MISMATCH = 'EXCEPTION_TICKET_MISMATCH'
GIT = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
       '-c', 'init.defaultBranch=main', '-c', 'core.autocrlf=false']
G100 = {'ticket': 'SEC-100', 'approver': 'Robin Example', 'from': '2025-12-01', 'expires': '2026-03-01'}
G101 = {'ticket': 'SEC-101', 'approver': 'Dana Example', 'from': '2026-03-01', 'expires': '2026-06-01'}
G102 = {'ticket': 'SEC-102', 'approver': 'Dana Example', 'from': '2026-06-01', 'expires': '2099-01-31'}


def git(cwd, *args):
    p = subprocess.run(GIT + list(args), cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()))
    return p.stdout


def decision(**over):
    d = {'authority': 'Dana Example', 'reason': 'adoption plan', 'decided_on': '2025-12-01',
         'expires': '2099-01-31', 'environment_reviewers': ['platform-approvers']}
    d.update(over)
    return d


def sx(ticket, expires, renews=None, approver='Dana Example'):
    item = {'finding': FP, 'ticket': ticket, 'explanation': 'fixture credential; rotation tracked on the ticket',
            'approver': approver, 'expires': expires, 'environment_reviewers': ['platform-approvers']}
    if renews is not None:
        item['renews'] = renews
    return item


def repo_doc(items):
    return {'schema_version': 2, 'register_id': 'repo',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2025-12-01'},
            'policies': [{'id': 'own', 'scope': {}, 'secret_exceptions': items, 'decision': decision()}]}


def central_doc(policies, **over):
    doc = {'schema_version': 2, 'register_id': 'central',
           'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2025-12-01'},
           'repositories': {REPOSITORY: {'team': 'payments', 'product': 'ledger'}}, 'policies': policies}
    doc.update(over)
    return doc


def make_repo(root, name, path, versions):
    """A repository whose `path` went through `versions` (dicts), one commit each. -> its directory."""
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, os.path.dirname(path)))
    git(d, 'init', '-q')
    for i, v in enumerate(versions):
        with io.open(os.path.join(d, path), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(json.dumps(v, indent=2, sort_keys=True) + '\n')
        git(d, 'add', '-A')
        git(d, 'commit', '-q', '-m', 'register v%d' % (i + 1))
    return d


def main():
    try:
        import exception_history as eh
        import policy_registration as pr
        import prove_exception_due as ped
        import yaml
    except ImportError as exc:
        print('UNKNOWN: cannot import the resolver, the due check or PyYAML: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='exception-history-')
    v1 = repo_doc([sx('SEC-100', '2026-03-01', approver='Robin Example')])
    v2 = repo_doc([sx('SEC-101', '2026-06-01', [G100])])
    v3 = repo_doc([sx('SEC-102', '2099-01-31', [G100, G101])])
    try:
        def resolve(repo, ref='HEAD', central_path='', **kw):
            return pr.resolve_from_ref(repo, ref, REG, central_path or os.path.join(work, 'no-central.json'),
                                       REPOSITORY, 'prod', 'push', {}, TODAY, **kw)

        def refusal(r, code):
            return [x for x in r.get('secret_exception_refusals') or [] if x.get('code') == code]

        # ---- H1 derived from git ---------------------------------------------------------------------
        good = make_repo(work, 'good', REG, [v1, v2, v3])
        r = resolve(good)
        sxs = r.get('secret_exceptions') or []
        print('  H1 renewed twice over three commits: state=%s in force=%s renewals=%s source=%s'
              % (r['state'], [x.get('finding') for x in sxs], [x.get('renewals') for x in sxs],
                 [x.get('history_source') for x in sxs]))
        check(r['state'] == 'POLICY_RESOLVED' and len(sxs) == 1 and sxs[0].get('renewals') == 2
              and sxs[0].get('history_source') == 'git' and 'SEC-100' in sxs[0].get('history', '')
              and 'SEC-101' in sxs[0].get('history', ''),
              'H1: the history was not derived from git (renewals 2, prior SEC-100, SEC-101): %r %r'
              % (r['state'], sxs or r.get('secret_exception_refusals')))

        # ---- H2 erased history -----------------------------------------------------------------------
        for label, renews in (('all of it', []), ('one grant', [G101])):
            erased = make_repo(work, 'erased-%d' % len(renews), REG,
                               [v1, v2, v3, repo_doc([sx('SEC-102', '2099-01-31', renews)])])
            r = resolve(erased)
            print('  H2 history erased (%s): state=%s routes=%s refused=%s'
                  % (label, r['state'], r.get('routes_to'), [x.get('code') for x in r.get('secret_exception_refusals') or []]))
            check(refusal(r, TAMPERED) and not r.get('secret_exceptions'),
                  'H2 (%s): an erased history was not refused %s: %r' % (label, TAMPERED, r.get('secret_exception_refusals')))
            check(r['state'] == TAMPERED and r.get('routes_to') == 'BLOCKED',
                  'H2 (%s): the resolution did not route BLOCKED on %s: %r / %r' % (label, TAMPERED, r['state'], r.get('routes_to')))

        # ---- H3 the cap binds the DERIVED count -------------------------------------------------------
        over = make_repo(work, 'over', REG, [v1, v2, v3, repo_doc([sx('SEC-103', '2099-06-30', [G100, G101, G102])])])
        r = resolve(over)
        check(refusal(r, 'EXCEPTION_RENEWAL_LIMIT') and not r.get('secret_exceptions'),
              'H3: three derived renewals under the kit cap of 2 were not EXCEPTION_RENEWAL_LIMIT: %r'
              % r.get('secret_exception_refusals'))

        # ---- H4 a shallow clone ----------------------------------------------------------------------
        shallow = os.path.join(work, 'shallow')
        git(work, 'clone', '-q', '--depth', '1', 'file://' + good.replace('\\', '/'), shallow)
        r = resolve(shallow)
        print('  H4 shallow clone: refused=%s in force=%s'
              % ([x.get('code') for x in r.get('secret_exception_refusals') or []], r.get('secret_exceptions')))
        check(refusal(r, UNVERIFIED) and not r.get('secret_exceptions'),
              'H4: a shallow clone was not EXCEPTION_HISTORY_UNVERIFIED (it must never read as zero renewals): %r %r'
              % (r.get('secret_exception_refusals'), r.get('secret_exceptions')))

        # ---- H5 the workflow's fetch: blob-less partial clone, measured ------------------------------
        git(good, 'config', 'uploadpack.allowFilter', 'true')
        partial = os.path.join(work, 'partial')
        git(work, 'clone', '-q', '--filter=blob:none', '--no-checkout', '--single-branch', '--branch', 'main',
            'file://' + good.replace('\\', '/'), partial)
        r = resolve(partial)
        sxs = r.get('secret_exceptions') or []
        check(len(sxs) == 1 and sxs[0].get('renewals') == 2,
              'H5: the blob-less partial clone did not verify the history: %r %r' % (sxs, r.get('secret_exception_refusals')))
        counts = git(partial, 'count-objects', '-v')
        print('  H5 blob-less partial clone: VERIFIED renewals=%s; %s'
              % ([x.get('renewals') for x in sxs], ' '.join(l for l in counts.split('\n') if l.startswith(('count', 'size-pack')))))

        # ---- H6 a central softening decision renewed in git with no renews ----------------------------
        soft = {'id': 'org-prod-da', 'scope': {'org': 'acme', 'environment_tier': 'prod'},
                'deploy_approval': {'self_review_prevented': 'not_required'}}
        c1 = central_doc([dict(soft, decision=decision(expires='2026-03-01', exception_ref='SEC-200'))])
        c2 = central_doc([dict(soft, decision=decision(expires='2099-01-31', exception_ref='SEC-201'))])
        kit = make_repo(work, 'kit', 'policy/policy-registration.json', [c1, c2])
        empty = os.path.join(work, 'empty-repo')
        os.makedirs(empty)
        git(empty, 'init', '-q')
        git(empty, 'commit', '-q', '--allow-empty', '-m', 'x')
        r = resolve(empty, central_path=os.path.join(kit, 'policy', 'policy-registration.json'))
        print('  H6 central softening renewed in git, no renews declared: state=%s routes=%s weakenings=%d'
              % (r['state'], r.get('routes_to'), len(r.get('weakenings') or [])))
        check(r['state'] == TAMPERED and r.get('routes_to') == 'BLOCKED' and not r.get('weakenings'),
              'H6: an erased decision history was not %s / BLOCKED with the softening withheld: %r %r %r'
              % (TAMPERED, r['state'], r.get('routes_to'), r.get('weakenings')))
        c3 = central_doc([dict(soft, decision=decision(expires='2099-01-31', exception_ref='SEC-201',
                                                       renews=[{'ticket': 'SEC-200', 'approver': 'Dana Example',
                                                                'from': '2025-12-01', 'expires': '2026-03-01'}]))])
        kit_ok = make_repo(work, 'kit-ok', 'policy/policy-registration.json', [c1, c3])
        r = resolve(empty, central_path=os.path.join(kit_ok, 'policy', 'policy-registration.json'))
        check(r['state'] == 'POLICY_RESOLVED' and any(w.get('control') == 'deploy-approval' and w.get('renewals') == 1
                                                     for w in r.get('weakenings') or []),
              'H6: a decision whose declared history matches git did not apply with renewals=1: %r %r'
              % (r['state'], r.get('weakenings')))

        # ---- H7 a central register outside git -------------------------------------------------------
        loose = os.path.join(work, 'loose-central.json')
        with io.open(loose, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(central_doc([{'id': 'sx', 'scope': {'org': 'acme'}, 'decision': decision(),
                                              'secret_exceptions': [sx('SEC-102', '2099-01-31')]}])))
        r = resolve(empty, central_path=loose)
        check(refusal(r, UNVERIFIED) and not r.get('secret_exceptions'),
              'H7: a central exception with no readable git history was not %s: %r' % (UNVERIFIED, r.get('secret_exception_refusals')))

        # ---- H8 the pure resolver with no history ----------------------------------------------------
        r = pr.resolve(None, v3, REPOSITORY, 'prod', 'push', {}, TODAY)
        check(refusal(r, UNVERIFIED) and not r.get('secret_exceptions'),
              'H8: the pure resolver with no history treated the exception as verified: %r' % r.get('secret_exceptions'))
        h = eh.history_from_texts([json.dumps(v1), json.dumps(v2), json.dumps(v3)])
        r = pr.resolve(None, v3, REPOSITORY, 'prod', 'push', {}, TODAY, history={'repository': h})
        check([x.get('renewals') for x in r.get('secret_exceptions') or []] == [2],
              'H8: a supplied history was not used: %r' % r.get('secret_exceptions'))

        # ---- H9 (C) the weekly Jira cross-check ------------------------------------------------------
        import exception_due as ed

        class JiraWithTickets(ped.FakeJira):
            def __init__(self, issues, **kw):
                ped.FakeJira.__init__(self, **kw)
                self.issues = issues

            def resolve(self, ref):
                self.calls.append(('resolve', ref))
                if ref not in self.issues:
                    return None, False, 'did not resolve (status 404)'
                return {'key': ref, 'fields': dict(self.issues[ref], status={'statusCategory': {'key': 'indeterminate'}})}, \
                    True, 'resolved'

        def issue(approver, links=(), text=''):
            return {'summary': 'secret exception %s' % FP, 'description': text + ' Approved by ' + approver,
                    'issuelinks': [{'outwardIssue': {'key': k}} for k in links]}

        cpath = os.path.join(work, 'xc-central.json')
        with io.open(cpath, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(central_doc([{'id': 'org', 'scope': {'org': 'acme'}, 'decision': decision(),
                                              'secret_exceptions': [sx('SEC-102', '2099-01-31', [G100, G101])]}])))
        env = {'TICKET_BACKEND': 'jira', 'JIRA_HOST': 'https://jira.example.invalid', 'JIRA_EMAIL': 'bot@example.invalid',
               'JIRA_TOKEN': 'tok-never-printed', 'JIRA_PROJECT': 'SEC'}
        cases = (
            ('consistent', {'SEC-102': issue('Dana Example', links=('SEC-100', 'SEC-101'))}, []),
            ('ticket missing', {}, ['does not exist']),
            ('other approver', {'SEC-102': issue('Someone Else', links=('SEC-100', 'SEC-101'))}, ['approver']),
            ('renewal not shown', {'SEC-102': issue('Dana Example', links=('SEC-101',))}, ['SEC-100']),
        )
        for label, issues, want in cases:
            fake = JiraWithTickets(issues)
            out = os.path.join(work, 'xc-%s.json' % label.replace(' ', '-'))
            summ = out + '.md'
            buf, old = io.StringIO(), sys.stdout
            sys.stdout = buf
            try:
                rc = ed.main(['--central', cpath, '--today', TODAY, '--out', out, '--summary', summ,
                              '--cross-check', '--apply'], env=env, backend_factory=lambda e: (fake, 'fake'))
            finally:
                sys.stdout = old
            doc = json.load(io.open(out, encoding='utf-8')) if os.path.exists(out) else {}
            md = io.open(summ, encoding='utf-8').read() if os.path.exists(summ) else ''
            mm = (doc.get('cross_check') or {}).get('mismatches') or []
            print('  H9 jira cross-check %-18s rc=%d state=%s mismatches=%s'
                  % (label, rc, (doc.get('cross_check') or {}).get('state'), [m.get('reasons') for m in mm]))
            if not want:
                check(not mm and (doc.get('cross_check') or {}).get('state') == 'CHECKED',
                      'H9 (%s): a consistent ticket was reported as a mismatch: %r' % (label, doc.get('cross_check')))
                continue
            check(mm and mm[0].get('code') == MISMATCH and all(any(w in r for r in mm[0].get('reasons') or [])
                                                                 for w in want),
                  'H9 (%s): no %s naming %r: %r' % (label, MISMATCH, want, doc.get('cross_check')))
            check(MISMATCH in md, 'H9 (%s): the run summary does not report %s' % (label, MISMATCH))
            check(rc == 1, 'H9 (%s): a mismatch did not exit 1 (listed): %d' % (label, rc))
            commented = [c for c in fake.calls if c[0] == 'comment' and MISMATCH in c[2]]
            if issues:
                check(commented, 'H9 (%s): the mismatch was not reported on the ticket: %r' % (label, fake.calls))
            check('tok-never-printed' not in json.dumps(doc) + md + buf.getvalue(),
                  'H9 (%s): the credential was printed' % label)

        # ---- H10 the gate never depends on Jira; the workflow fetch is blob-less ---------------------
        src = io.open(os.path.join(ROOT, 'scripts', 'policy_registration.py'), encoding='utf-8').read() + \
            io.open(os.path.join(ROOT, 'scripts', 'exception_history.py'), encoding='utf-8').read()
        check('reconcile_tickets' not in src and 'JIRA_' not in src,
              'H10: the resolver (the gate\'s input) reads the tracker: the gate must never depend on Jira')
        act = io.open(os.path.join(ROOT, '.github', 'actions', 'resolve-policy', 'action.yml'), encoding='utf-8').read()
        check('--filter=blob:none' in act and '--depth=1' not in act,
              'H10: the resolve-policy action does not fetch the default branch blob-less with history '
              '(a depth-1 fetch makes every exception UNVERIFIED)')

        # ---- H11 taxonomy ----------------------------------------------------------------------------
        tax = yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
        text = json.dumps(tax, default=str)
        for term in (TAMPERED, UNVERIFIED, MISMATCH):
            check('"%s"' % term in text, 'H11: %s is not a registered taxonomy term' % term)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: an exception\'s renewals are derived from the git history of its protected register file; a declared '
          'history shorter than git shows is EXCEPTION_HISTORY_TAMPERED (BLOCKED); the cap binds the derived count; a '
          'history git cannot show (shallow clone, no git) is EXCEPTION_HISTORY_UNVERIFIED and refused, never zero; '
          'the workflow\'s blob-less fetch shows it; the weekly check holds each ticket in Jira to the same approver '
          'and renewals and reports EXCEPTION_TICKET_MISMATCH, and the gate never depends on Jira.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
