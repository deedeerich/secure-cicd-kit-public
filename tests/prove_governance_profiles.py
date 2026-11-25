#!/usr/bin/env python3
"""The two governance profiles, each held positive, negative and adversarial, and every guard
reached by a named mutant (KDEC-052 item 11, KE-02; KDEC-059).

Every case runs in BOTH profiles (personal: the owner authorizes alone; employer: assigned
reviewers, separation of duties), through scripts/governance_gate.py's evaluate() as shipped.

  POSITIVE  P-1 a routine green change (docs only): merge_eligible
            P-2 a protected change with the profile's authorizer on THIS head: authorized
  NEGATIVE  N-1 the trusted check failed; N-2 missing; N-3 inconclusive (in progress, skipped,
            neutral, cancelled): hold, each by its own rule
  ADVERSARIAL (each HOLDS in both profiles; no authorization given)
            A-1 the PR edits the classifier (scripts/governance_gate.py)
            A-2 the PR edits protected_paths.py / CHANGE_GUARDED
            A-3 the PR edits the floor (capability-floor.json)
            A-4 the PR edits the merge logic (.github/workflows/governance-gate.yml)
            A-5 the PR switches the profile (governance-profile.json); end to end in git: the base's
                profile decides, so employer -> personal is judged as employer and holds
            A-6 the PR adds a workflow emitting a fake "Self-test required": held by classification
                AND by source (impostor_check); a fake check alone, on a routine change, holds too
            A-7 the PR edits the change log only
            A-8 the PR edits self-test.yml so its own "Self-test required" passes: held
            A-9 a protected file RENAMED to a routine path (end to end): held
  AUTHORIZATION (the authorizer cannot be forged from inside the PR)
            personal: a comment for another head sha, a non-owner comment, an edited comment, a
                      placeholder owner_login, a review in place of the comment: hold
            employer: the author approving, a committer approving, an approval on an old commit, a
                      non-reviewer approving, changes requested outstanding, membership unreadable,
                      required_approvals 0, the owner's comment in place of a review: hold
  BASE-SIDE an authorized change that breaks the floor (end to end): hold (floor_breached)
  DEPENDABOT a verified Dependabot PR is delegated; one that touches the machinery is not
  WORKFLOW  W-1..W-7 governance-gate.yml never runs PR code in its privileged context
  MUTANTS   M-classify, M-machinery, M-impostor, M-source, M-missing, M-inconclusive, M-authorize,
            M-head-sha, M-owner, M-sod-author, M-sod-pusher, M-stale-review, M-profile-from-base,
            M-no-renames: each guard removed lets its negative through (the negative reaches it)

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import yaml  # noqa: E402
import governance_gate as gg  # noqa: E402

FAILS = []
HEAD = 'a' * 40
OLD = 'b' * 40
TS = '.github/workflows/self-test.yml'


def check(cond, label, detail=''):
    print('%s %s%s' % ('ok  ' if cond else 'FAIL', label, (': %s' % (detail,)) if not cond and detail != '' else ''))
    if not cond:
        FAILS.append(label)


def mutant(old, new, name):
    path = os.path.join(ROOT, 'scripts', 'governance_gate.py')
    src = io.open(path, encoding='utf-8').read()
    if old not in src:
        FAILS.append('%s could not be applied (the guard text moved): %r' % (name, old[:60]))
        return None
    mod = types.ModuleType(name)
    mod.__file__ = path
    exec(compile(src.replace(old, new, 1), path, 'exec'), mod.__dict__)
    return mod


def killed(name, mod, still_held):
    if mod is None:
        return
    check(not still_held(mod), '%s killed (the negative passes once the guard is removed)' % name)


def base_cfg():
    return json.loads(io.open(os.path.join(ROOT, gg.CONFIG), encoding='utf-8').read())


def cfg_for(profile):
    c = base_cfg()
    c['profile'] = profile
    c['profiles']['personal']['owner_login'] = 'owner'
    c['profiles']['employer'].update(reviewer_teams=['org/reviewers'], reviewer_logins=[], required_approvals=1)
    return c


MEMBERS = {'org/reviewers': ['rev1', 'rev2', 'dev']}


def run_(suite, path, conclusion='success', status='completed', name='Self-test required', app='github-actions', i=1):
    c = {'id': i, 'name': name, 'status': status, 'conclusion': conclusion, 'app': {'slug': app},
         'check_suite': {'id': suite}, 'started_at': '2026-11-13T00:00:0%dZ' % i}
    return c, {'check_suite_id': suite, 'path': path}


def green():
    c, r = run_(9, TS)
    return [c], [r]


def pr(author='dev'):
    return {'number': 7, 'head_sha': HEAD, 'author': author}


AUTH_COMMENT = [{'user': {'login': 'owner'}, 'body': '/kit-authorize ' + HEAD,
                 'created_at': '2026-11-13T01:00:00Z', 'updated_at': '2026-11-13T01:00:00Z'}]
AUTH_REVIEW = [{'user': {'login': 'rev1'}, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': '2026-11-13T01:00:00Z'}]
COMMITS = [{'author': {'login': 'dev'}, 'committer': {'login': 'web-flow'}, 'commit': {'verification': {'verified': True}}}]


def authz(profile):
    return {'comments': AUTH_COMMENT} if profile == 'personal' else {'reviews': AUTH_REVIEW}


def ev(m, profile, changed, checks=None, runs=None, **kw):
    cr, wr = green()
    kw.setdefault('commits', COMMITS)
    kw.setdefault('members', MEMBERS)
    return m.evaluate(cfg_for(profile), kw.pop('pr', pr()), changed, cr if checks is None else checks,
                      wr if runs is None else runs, **kw)


def rules(rec):
    return [r['rule'] for r in rec['rules']]


def positive_negative(profile):
    t = '[%s] ' % profile
    r = ev(gg, profile, ['docs/guide.md', 'README.md'])
    check(r['decision'] == 'merge_eligible' and not r['rules'], t + 'P-1 a routine green change: merge_eligible', r)
    r = ev(gg, profile, ['scripts/governance_gate.py'], **authz(profile))
    check(r['decision'] == 'authorized', t + 'P-2 a protected change with its authorizer on this head: authorized', r)
    c, w = run_(9, TS, conclusion='failure')
    r = ev(gg, profile, ['docs/guide.md'], [c], [w])
    check(r['decision'] == 'hold' and 'check_failed' in rules(r), t + 'N-1 the trusted check failed: hold', r)
    r = ev(gg, profile, ['docs/guide.md'], [], [])
    check(r['decision'] == 'hold' and 'check_missing' in rules(r), t + 'N-2 the trusted check missing: hold', r)
    for st, concl in (('in_progress', None), ('completed', 'skipped'), ('completed', 'neutral'), ('completed', 'cancelled')):
        c, w = run_(9, TS, conclusion=concl, status=st)
        r = ev(gg, profile, ['docs/guide.md'], [c], [w])
        check(r['decision'] == 'hold' and 'check_inconclusive' in rules(r),
              t + 'N-3 the trusted check %s/%s (inconclusive): hold' % (st, concl), r)
    r = ev(gg, profile, ['docs/guide.md'], pr=dict(pr(), draft=True))
    check(r['decision'] == 'hold' and 'draft' in rules(r), t + 'N-4 a draft: hold', r)


ADVERSARIAL = [
    ('A-1 the PR edits the classifier', ['scripts/governance_gate.py']),
    ('A-2 the PR edits protected_paths.py (CHANGE_GUARDED)', ['scripts/protected_paths.py', 'docs/assurance/PROTECTED_CHANGE_LOG.md']),
    ('A-3 the PR edits the floor', ['capability-floor.json']),
    ('A-4 the PR edits the merge logic', ['.github/workflows/governance-gate.yml']),
    ('A-5 the PR switches the profile', ['governance-profile.json']),
    ('A-6 the PR adds a workflow emitting a fake check', ['.github/workflows/fake-selftest.yml']),
    ('A-7 the PR edits the change log only', ['docs/assurance/PROTECTED_CHANGE_LOG.md']),
    ('A-8 the PR edits self-test.yml', [TS]),
]


def adversarial(profile):
    t = '[%s] ' % profile
    for label, changed in ADVERSARIAL:
        r = ev(gg, profile, changed)
        check(r['decision'] == 'hold' and 'awaiting_authorizer' in rules(r) and r['protected'],
              t + label + ': hold for the authorizer', r)
    # A-6 by source: the fake check alongside the real one, and the fake one alone.
    real, rw = run_(9, TS, i=1)
    fake, fw = run_(11, '.github/workflows/fake-selftest.yml', i=2)
    r = ev(gg, profile, ['.github/workflows/fake-selftest.yml'], [real, fake], [rw, fw])
    check(r['decision'] == 'hold' and 'impostor_check' in rules(r), t + 'A-6b the fake check beside the real one: impostor_check', r)
    neg_imp = lambda m: ev(m, profile, ['docs/guide.md'], [real, fake], [rw, fw])['decision'] == 'hold'
    check(neg_imp(gg), t + 'A-6c a fake check on a routine change (real one green): hold')
    neg_src = lambda m: ev(m, profile, ['docs/guide.md'], [fake], [fw])['decision'] == 'hold'
    check(neg_src(gg), t + 'A-6d the fake check alone: hold (missing from its trusted source)')
    stat, sw = run_(13, TS, app='some-app', i=3)
    check(ev(gg, profile, ['docs/guide.md'], [real, stat], [rw, sw])['decision'] == 'hold',
          t + 'A-6e the trusted name from another app: hold')
    r = ev(gg, profile, [TS], **authz(profile))
    check(r['self_defined_checks'] == ['Self-test required'], t + 'A-8b a self-test.yml change is recorded as self-defined', r)
    if profile == 'personal':
        killed('M-impostor', mutant('        if impostors:', '        if False:', 'm_imp'), neg_imp)
        killed('M-source', mutant("            if app == 'github-actions' and run is not None and _wf_path(run) == wf:",
                                  '            if True:', 'm_src'), neg_src)
        neg_c = lambda m: ev(m, profile, ['scripts/governance_gate.py'])['decision'] == 'hold'
        killed('M-classify', mutant('    out = {}\n    for p in changed:', '    out = {}\n    for p in []:', 'm_cls'), neg_c)
        empty = cfg_for(profile)
        empty['classes'] = []
        neg_m = lambda m: m.evaluate(empty, pr(), ['docs/assurance/PROTECTED_CHANGE_LOG.md'], *green(),
                                     commits=COMMITS)['decision'] == 'hold'
        check(neg_m(gg), t + 'A-7b the change log is protected by the MACHINERY floor even when the profile lists no class')
        killed('M-machinery', mutant('        if any(_match(p, m) for m in MACHINERY):', '        if False:', 'm_mach'), neg_m)
        neg_miss = lambda m: ev(m, profile, ['docs/guide.md'], [], [])['decision'] == 'hold'
        killed('M-missing', mutant("            probs.append(('check_missing', ", "            (('check_missing', ", 'm_miss'), neg_miss)
        c, w = run_(9, TS, conclusion='skipped')
        neg_inc = lambda m: ev(m, profile, ['docs/guide.md'], [c], [w])['decision'] == 'hold'
        killed('M-inconclusive', mutant("        elif last.get('conclusion') != 'success':",
                                        "        elif last.get('conclusion') not in ('success', 'skipped', 'neutral', 'cancelled'):",
                                        'm_inc'), neg_inc)
        neg_a = lambda m: ev(m, profile, ['scripts/governance_gate.py'])['decision'] == 'hold'
        killed('M-authorize', mutant('        if not ok:\n            hold(why[0]', '        if False:\n            hold(why[0]', 'm_auth'), neg_a)


def personal_forgery():
    t = '[personal] '
    p = 'personal'
    ch = ['scripts/governance_gate.py']
    other = [dict(AUTH_COMMENT[0], body='/kit-authorize ' + OLD)]
    neg_sha = lambda m: ev(m, p, ch, comments=other)['decision'] == 'hold'
    check(neg_sha(gg), t + 'F-1 an authorization for another head sha (a new push moved the head): hold')
    killed('M-head-sha', mutant('        if m and m.group(1) == head:', '        if m:', 'm_sha'), neg_sha)
    stranger = [dict(AUTH_COMMENT[0], user={'login': 'dev'})]
    neg_own = lambda m: ev(m, p, ch, comments=stranger)['decision'] == 'hold'
    check(neg_own(gg), t + 'F-2 the PR author (not the owner) comments /kit-authorize: hold')
    killed('M-owner', mutant("        if ((c.get('user') or {}).get('login') or '').lower() != owner.lower():",
                             "        if False:", 'm_owner'), neg_own)
    edited = [dict(AUTH_COMMENT[0], updated_at='2026-11-13T02:00:00Z')]
    check(ev(gg, p, ch, comments=edited)['decision'] == 'hold', t + 'F-3 an edited authorization comment: hold')
    c = cfg_for(p)
    c['profiles']['personal']['owner_login'] = 'replace-me-owner-login'
    r = gg.evaluate(c, pr('replace-me-owner-login'), ch, *green(), comments=[dict(AUTH_COMMENT[0], user={'login': 'replace-me-owner-login'})])
    check(r['decision'] == 'hold' and 'authorizer_unconfigured' in rules(r), t + 'F-4 a placeholder owner_login authorizes nothing', r)
    check(ev(gg, p, ch, reviews=AUTH_REVIEW)['decision'] == 'hold', t + 'F-5 a review in place of the owner\'s record: hold')
    check(ev(gg, p, ch, comments=[dict(AUTH_COMMENT[0], body='LGTM\n/kit-authorize ' + HEAD)])['decision'] == 'hold',
          t + 'F-6 the authorization must be the first line: hold')
    r = ev(gg, p, ch, comments=AUTH_COMMENT, pr=pr('owner'),
           commits=[{'author': {'login': 'owner'}, 'committer': {'login': 'owner'}}])
    check(r['decision'] == 'authorized', t + 'F-P the owner authorizes her own pull request: no second human is required', r)


def employer_forgery():
    t = '[employer] '
    p = 'employer'
    ch = ['scripts/governance_gate.py']
    me = [dict(AUTH_REVIEW[0], user={'login': 'dev'})]
    other_commits = [{'author': {'login': 'rev2'}, 'committer': {'login': 'web-flow'}}]
    neg_author = lambda m: ev(m, p, ch, reviews=me, commits=other_commits)['decision'] == 'hold'
    check(neg_author(gg), t + 'E-1 the author approves (and pushed nothing): hold')
    killed('M-sod-author', mutant("and u in allowed and u != author and u not in pushers", "and u in allowed and u not in pushers",
                                  'm_sod_a'), neg_author)
    pusher = [{'author': {'login': 'dev'}, 'committer': {'login': 'web-flow'}}, {'author': {'login': 'rev1'}, 'committer': {'login': 'rev1'}}]
    neg_push = lambda m: ev(m, p, ch, reviews=AUTH_REVIEW, commits=pusher)['decision'] == 'hold'
    check(neg_push(gg), t + 'E-2 a reviewer who pushed a commit approves: hold')
    killed('M-sod-pusher', mutant("and u in allowed and u != author and u not in pushers", "and u in allowed and u != author",
                                  'm_sod_p'), neg_push)
    stale = [dict(AUTH_REVIEW[0], commit_id=OLD)]
    neg_stale = lambda m: ev(m, p, ch, reviews=stale)['decision'] == 'hold'
    check(neg_stale(gg), t + 'E-3 an approval on an older commit: hold')
    killed('M-stale-review', mutant(" and r.get('commit_id') == head\n", "\n", 'm_stale'), neg_stale)
    outsider = [dict(AUTH_REVIEW[0], user={'login': 'someone'})]
    check(ev(gg, p, ch, reviews=outsider)['decision'] == 'hold', t + 'E-4 an approval from outside the assigned reviewers: hold')
    cr = AUTH_REVIEW + [{'user': {'login': 'rev2'}, 'state': 'changes_requested', 'commit_id': HEAD, 'submitted_at': '2026-11-13T02:00:00Z'}]
    r = ev(gg, p, ch, reviews=cr)
    check(r['decision'] == 'hold' and 'changes_requested' in rules(r), t + 'E-5 changes requested outstanding: hold', r)
    r = ev(gg, p, ch, reviews=AUTH_REVIEW, members={})
    check(r['decision'] == 'hold' and 'reviewers_unknown' in rules(r), t + 'E-6 team membership unreadable: hold', r)
    c = cfg_for(p)
    c['profiles']['employer']['required_approvals'] = 0
    r = gg.evaluate(c, pr(), ch, *green(), reviews=AUTH_REVIEW, commits=COMMITS, members=MEMBERS)
    check(r['decision'] == 'hold' and 'policy_misconfigured' in rules(r), t + 'E-7 required_approvals 0: hold', r)
    check(ev(gg, p, ch, comments=AUTH_COMMENT)['decision'] == 'hold', t + 'E-8 the owner\'s comment in place of a review: hold')
    c['profiles']['employer'].update(required_approvals=2)
    r = gg.evaluate(c, pr(), ch, *green(), reviews=AUTH_REVIEW, commits=COMMITS, members=MEMBERS)
    check(r['decision'] == 'hold', t + 'E-9 one approval where two are required: hold', r)
    r = gg.evaluate(c, pr(), ch, *green(), reviews=AUTH_REVIEW + [dict(AUTH_REVIEW[0], user={'login': 'rev2'})],
                    commits=COMMITS, members=MEMBERS)
    check(r['decision'] == 'authorized', t + 'E-P two assigned reviewers, neither author nor committer: authorized', r)


def dependabot():
    db = {'author': {'login': gg.DEPENDABOT}, 'committer': {'login': 'web-flow'}, 'commit': {'verification': {'verified': True}}}
    for p in gg.PROFILES:
        r = ev(gg, p, ['.github/workflows/reusable-security.yml'], pr=pr(gg.DEPENDABOT), commits=[db])
        check(r['decision'] == 'delegated', '[%s] D-1 a verified Dependabot pin bump: delegated to the triage' % p, r)
        r = ev(gg, p, ['.github/workflows/governance-gate.yml'], pr=pr(gg.DEPENDABOT), commits=[db])
        check(r['decision'] == 'hold', '[%s] D-2 a Dependabot bump inside the gate itself: hold' % p, r)
        human = dict(db, author={'login': 'dev'})
        r = ev(gg, p, ['.github/workflows/reusable-security.yml'], pr=pr(gg.DEPENDABOT), commits=[db, human])
        check(r['decision'] == 'hold', '[%s] D-3 a human commit on a Dependabot branch: not delegated, hold' % p, r)


# ---- end to end, in a real git repository, through main() ----

def git(d, *a):
    r = subprocess.run(['git', '-C', d] + list(a), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(a), r.stderr.decode('utf-8', 'replace')))
    return r.stdout.decode('utf-8', 'replace').strip()


def write(d, rel, text):
    path = os.path.join(d, *rel.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def repo(work, name, base_cfg_doc, mutate):
    d = os.path.join(work, name)
    os.makedirs(d)
    git(d, 'init', '-q')
    git(d, 'config', 'user.email', 't@example.invalid')
    git(d, 'config', 'user.name', 't')
    git(d, 'config', 'core.autocrlf', 'false')
    write(d, gg.CONFIG, json.dumps(base_cfg_doc, indent=1))
    write(d, 'scripts/governance_gate.py', '# the gate\n' + 'x = 1\n' * 40)
    write(d, 'docs/assurance/PROTECTED_CHANGE_LOG.md', '| date | decision | paths | what |\n|---|---|---|---|\n')
    for rel in ('capability-floor.json', 'scanner-registry.yaml'):
        write(d, rel, io.open(os.path.join(ROOT, rel), encoding='utf-8').read())
    write(d, 'docs/guide.md', 'guide\n')
    git(d, 'add', '-A')
    git(d, 'commit', '-q', '-m', 'base')
    base = git(d, 'rev-parse', 'HEAD')
    mutate(d)
    git(d, 'add', '-A')
    git(d, 'commit', '-q', '-m', 'head')
    return d, base, git(d, 'rev-parse', 'HEAD')


def data(work, name, head, profile, **extra):
    dd = os.path.join(work, name + '-data')
    os.makedirs(dd)
    cr, wr = green()
    docs = {'pr.json': {'number': 7, 'head': {'sha': head}, 'user': {'login': 'dev'}},
            'check-runs.json': cr, 'workflow-runs.json': {'workflow_runs': wr},
            'reviews.json': [], 'comments.json': [], 'commits.json': COMMITS, 'members.json': MEMBERS}
    if 'comments' in extra:
        extra['comments'] = [dict(c, body=c['body'].replace(HEAD, head)) for c in extra['comments']]
    for k, v in extra.items():
        docs[k + '.json'] = v
    for k, v in docs.items():
        io.open(os.path.join(dd, k), 'w', encoding='utf-8').write(json.dumps(v))
    return dd


def e2e(m, work, name, base_doc, mutate, profile_for_data, **extra):
    d, base, head = repo(work, name, base_doc, mutate)
    dd = data(work, name, head, profile_for_data, **extra)
    args = types.SimpleNamespace(repo=d, base=base, head=head, data_dir=dd, today='2026-11-13')
    return m.run(args)


def end_to_end(work):
    emp = cfg_for('employer')
    per = cfg_for('personal')

    def switch(d):
        doc = copy.deepcopy(emp)
        doc['profile'] = 'personal'
        write(d, gg.CONFIG, json.dumps(doc, indent=1))
        write(d, 'docs/assurance/PROTECTED_CHANGE_LOG.md', '| date | decision | paths | what |\n|---|---|---|---|\n'
              '| 2026-11-13 | KDEC-999 | governance-profile.json | downgrade |\n')
    n = [0]

    def neg_switch(m):
        n[0] += 1
        r = m.run(types.SimpleNamespace(**vars(_switch_args(work, emp, switch, n[0]))))
        return r is not None and r['decision'] == 'hold'
    r = e2e(gg, work, 'switch', emp, switch, 'employer', comments=AUTH_COMMENT)
    check(r is not None and r['decision'] == 'hold' and r['profile'] == 'employer' and 'awaiting_authorizer' in rules(r),
          'A-5e employer -> personal, with the owner\'s comment: judged by the BASE profile (employer) and held', r)
    killed('M-profile-from-base', mutant("    cfg = json.loads(show(a.repo, a.base, CONFIG) or '')",
                                         "    cfg = json.loads(show(a.repo, a.head, CONFIG) or '')", 'm_prof'), neg_switch)

    def rename(d):
        git(d, 'mv', 'scripts/governance_gate.py', 'docs/notes-gate.py')
    for prof, doc in (('personal', per), ('employer', emp)):
        r = e2e(gg, work, 'rename-' + prof, doc, rename, prof)
        check(r is not None and r['decision'] == 'hold' and 'scripts/governance_gate.py' in r['protected'],
              '[%s] A-9 a protected file renamed to a routine path: the old path is read, hold' % prof, r)
    neg_rn = lambda m: (lambda r: r is not None and r['decision'] == 'hold')(
        e2e(m, work, 'rename-m%d' % id(m), per, rename, 'personal'))
    killed('M-no-renames', mutant("'--name-only', '--no-renames', mb", "'--name-only', mb", 'm_rn'), neg_rn)
    for prof, doc in (('personal', per), ('employer', emp)):
        r = e2e(gg, work, 'docs-' + prof, doc, lambda d: write(d, 'docs/guide.md', 'better guide\n'), prof)
        check(r is not None and r['decision'] == 'merge_eligible', '[%s] P-1e a routine docs change end to end: merge_eligible' % prof, r)

    def shrink(d):
        f = json.loads(io.open(os.path.join(d, 'capability-floor.json'), encoding='utf-8').read())
        f['floor'] = [e for e in f['floor'] if e['capability'] != 'sast-go']
        write(d, 'capability-floor.json', json.dumps(f, indent=1))
        write(d, 'docs/assurance/PROTECTED_CHANGE_LOG.md', '| date | decision | paths | what |\n|---|---|---|---|\n'
              '| 2026-11-13 | KDEC-999 | capability-floor.json | drop go |\n')
    r = e2e(gg, work, 'shrink', per, shrink, 'personal', comments=AUTH_COMMENT)
    check(r is not None and r['decision'] == 'hold' and 'floor_breached' in rules(r) and 'awaiting_authorizer' not in rules(r),
          '[personal] B-1 an AUTHORIZED change that drops a scanner without a tombstone: hold (floor_breached, base-side)', r)
    r = e2e(gg, work, 'nolog', per, lambda d: write(d, 'scripts/protected_paths.py', 'x = 2\n'), 'personal', comments=AUTH_COMMENT)
    check(r is not None and r['decision'] == 'hold' and 'change_record' in rules(r),
          '[personal] B-2 an authorized guarded change with no change-log row: hold (change_record, base-side)', r)
    d, base, head = repo(work, 'wrong-head', per, lambda d: write(d, 'docs/guide.md', 'x\n'))
    dd = data(work, 'wrong-head', OLD, 'personal')
    check(gg.run(types.SimpleNamespace(repo=d, base=base, head=head, data_dir=dd, today='2026-11-13')) is None,
          'U-1 the fetched head is not the PR\'s head: could not decide (exit 2, the workflow holds)')


def _switch_args(work, emp, switch, k):
    d, base, head = repo(work, 'switch-m%d' % k, emp, switch)
    dd = data(work, 'switch-m%d' % k, head, 'employer', comments=AUTH_COMMENT)
    return types.SimpleNamespace(repo=d, base=base, head=head, data_dir=dd, today='2026-11-13')


def workflow():
    path = os.path.join(ROOT, '.github', 'workflows', 'governance-gate.yml')
    if not os.path.isfile(path):
        check(False, 'W-0 .github/workflows/governance-gate.yml exists')
        return
    wf = yaml.safe_load(io.open(path, encoding='utf-8').read())
    on = wf.get('on', wf.get(True)) or {}
    check(set(on) <= {'pull_request_target', 'workflow_run', 'issue_comment', 'workflow_dispatch'} and 'pull_request' not in on,
          'W-1 the gate runs only on base-side events (never pull_request)', sorted(on))
    check(wf.get('permissions') == {}, 'W-2 nothing is inherited: top-level permissions {}')
    steps = [(j, s) for j, job in wf['jobs'].items() for s in job.get('steps') or []]
    cos = [s for _j, s in steps if 'actions/checkout' in str(s.get('uses'))]
    check(bool(cos) and all((s.get('with') or {}).get('persist-credentials') is False
                            and 'default_branch' in str((s.get('with') or {}).get('ref'))
                            and 'head' not in str((s.get('with') or {}).get('ref')) for s in cos),
          'W-3 every checkout is the DEFAULT branch, without persisted credentials (never the PR head)')
    runs = [str(s.get('run') or '') for _j, s in steps]
    check(not any('${{' in r for r in runs), 'W-4 no run: block holds an expression (PR data reaches scripts through env:)')
    gate = [s for _j, s in steps if 'governance_gate.py' in str(s.get('run'))]
    check(bool(gate) and all(not any(k in (s.get('env') or {}) for k in ('GH_TOKEN', 'GITHUB_TOKEN')) for s in gate),
          'W-5 the step that runs the checker holds no token')
    bad = ('git checkout', 'git switch', 'git worktree', 'pip install -r', 'npm ', 'make ', 'bash pr-', 'source ')
    check(not any(b in r for r in runs for b in bad), 'W-6 nothing from the pull request is checked out or executed')
    merge = [j for j in wf['jobs'].values() if 'gh pr merge --auto' in str(j)]
    check(len(merge) == 1 and "'merge_eligible'" in str(merge[0].get('if')) and "'authorized'" in str(merge[0].get('if')),
          'W-7 auto-merge is armed only on merge_eligible or authorized')
    st = yaml.safe_load(io.open(os.path.join(ROOT, TS), encoding='utf-8').read())
    on2 = st.get('on', st.get(True)) or {}
    check('pull_request' in on2, 'W-8 (why this exists) Self-test still runs on pull_request, the PR\'s own definition')


def main():
    work = tempfile.mkdtemp(prefix='gov-profiles-')
    try:
        for p in gg.PROFILES:
            positive_negative(p)
            adversarial(p)
        personal_forgery()
        employer_forgery()
        dependabot()
        r = gg.evaluate(dict(cfg_for('personal'), profile='team'), pr(), ['docs/a.md'], *green())
        check(r['decision'] == 'hold' and 'profile_unreadable' in rules(r), 'U-2 an unknown base profile holds everything', r)
        r = gg.evaluate(cfg_for('personal'), pr(), [], *green())
        check(r['decision'] == 'hold' and 'diff_unreadable' in rules(r), 'U-3 an empty or unread diff holds', r)
        end_to_end(work)
        workflow()
    except Exception as e:  # noqa: BLE001 -- an unexpected error is UNKNOWN, never a pass
        import traceback
        traceback.print_exc()
        print('UNKNOWN: %s' % e)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print('FAIL: %d violation(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: both profiles hold every adversarial case; routine green merges; every guard is reached.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
