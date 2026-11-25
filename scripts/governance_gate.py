#!/usr/bin/env python3
"""The governance gate: a risk-based merge decision made from the BASE side, reading the pull
request as data (KDEC-052 item 11, KE-02; KDEC-059).

WHY THIS EXISTS

    "Self-test required" runs on `pull_request`, so the pull request's own self-test.yml and
    validators produce it (tests/prove_scanner_floor_shrink.py B-1): a pull request can redefine the
    check that judges it, or add a workflow emitting a check with the same name. This gate is run
    by .github/workflows/governance-gate.yml from the DEFAULT branch (pull_request_target,
    workflow_run, issue_comment, workflow_dispatch -- never `pull_request`). It checks out nothing
    from the pull request: the PR's commits are fetched as git OBJECTS and read with `git diff` /
    `git show`, its checks, reviews and comments through the API, as JSON. This file, the profile it
    reads (governance-profile.json, read from the BASE commit) and the checkers it imports
    (capability_floor, protected_paths) are the base's copies. Nothing the pull request contains is
    executed, so nothing it contains can change the checker or the result it reports.

THE DECISION (one of four; a state, never a boolean)

    merge_eligible  routine: no protected path changed, every trusted check passed from its trusted
                    workflow, the base-side checks hold. The workflow arms `gh pr merge --auto`.
    authorized      protected, and the profile's authorizer recorded authorization on THIS head
                    commit, and every check above holds. The workflow arms auto-merge.
    hold            anything else. Each reason is a named rule. A failed, missing or inconclusive
                    check holds; an impostor check (the trusted name from any other source) holds;
                    a protected change without its authorizer holds. The workflow disarms auto-merge.
    delegated       a Dependabot pull request (author and every commit dependabot[bot], verified)
                    that touches no governance machinery: the Dependabot triage decides it.

PROFILES (governance-profile.json `profile`, read from the BASE; an unknown profile holds everything)

    personal   the owner is the authorizer; no second human is ever required. Authorization is a PR
               comment by `owner_login` whose first line is `/kit-authorize <40-hex head sha>`,
               unedited. A new push moves the head, so an authorization never carries to new code.
    employer   approvals from the assigned reviewers (team members, or reviewer_logins) on the
               current head commit; the author and anyone who pushed a commit never count
               (separation of duties); any reviewer's latest review requesting changes holds.

CLASSIFICATION is by security/operational impact, not "contains code": a path is protected when it
matches a class in the base profile OR the MACHINERY floor below, which the profile cannot lower.
Renames are read as a delete plus an add (`--no-renames`), so moving a protected file is protected.

EXIT  0 decided (any decision)   2 could not decide (the workflow then holds and reports an error)
"""
import argparse
import datetime
import fnmatch
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = 'governance-profile.json'
CHANGE_LOG = 'docs/assurance/PROTECTED_CHANGE_LOG.md'
PROFILES = ('personal', 'employer')
DECISIONS = ('merge_eligible', 'authorized', 'hold', 'delegated')
PLACEHOLDER = re.compile(r'your_org|your_owner|replace-me', re.I)
DEPENDABOT = 'dependabot[bot]'
AUTHORIZE = re.compile(r'^/kit-authorize\s+([0-9a-f]{40})\s*$')
# The floor the profile cannot lower: the gate, its configuration, its workflow, the checkers it
# imports, the files that decide "Self-test required", the floor, the change log and the owners.
MACHINERY = ('scripts/governance_gate.py', CONFIG, '.github/workflows/governance-gate.yml',
             'tests/prove_governance_profiles.py', 'scripts/protected_paths.py', 'scripts/capability_floor.py',
             'scripts/selftest_required.py', '.github/workflows/self-test.yml', 'capability-floor.json',
             'scanner-registry.yaml', CHANGE_LOG, 'CODEOWNERS',
             '.github/CODEOWNERS', 'docs/CODEOWNERS', '.github/')
# Executable or trust boundaries wherever they appear in a tree.
STRUCTURAL = ('**/action.yml', '**/action.yaml', '**/Dockerfile', '**/*.tf', '.gitattributes', '.gitmodules',
              '**/.pre-commit-config.yaml')


def _match(path, pat):
    if pat.endswith('/'):
        return path.startswith(pat)
    if pat.startswith('**/'):
        return fnmatch.fnmatchcase(path, pat[3:]) or fnmatch.fnmatchcase(path.rsplit('/', 1)[-1], pat[3:])
    return path == pat or fnmatch.fnmatchcase(path, pat)


def classify(changed, cfg):
    """-> {path: (class, why)} for every protected path; unlisted paths are routine."""
    out = {}
    for p in changed:
        if any(_match(p, m) for m in MACHINERY):
            out[p] = ('governance_machinery', 'the gate, its profile, its checkers or the change log')
            continue
        hit = None
        for c in (cfg.get('classes') or []):
            if any(_match(p, pat) for pat in (c.get('paths') or [])):
                hit = (str(c.get('class')), str(c.get('why') or ''))
                break
        if hit is None and any(_match(p, s) for s in STRUCTURAL):
            hit = ('security_control', 'an executable or trust boundary')
        if hit:
            out[p] = hit
    return out


def _wf_path(run):
    return str((run or {}).get('path') or '').split('@', 1)[0]


def evaluate_checks(cfg, check_runs, workflow_runs, changed):
    """-> (problems [(rule, reason)], self_defined [names]). Trust is per SOURCE, not per name."""
    probs, self_defined = [], []
    suites = {}
    for r in workflow_runs:
        if r.get('check_suite_id') is not None:
            suites[r['check_suite_id']] = r
    trusted = cfg.get('trusted_checks') or []
    if not trusted:
        probs.append(('no_trusted_checks', 'the base profile names no trusted check, so nothing shows the change was tested'))
    for t in trusted:
        name, wf = t.get('name'), t.get('workflow')
        mine, impostors = [], []
        for c in check_runs:
            if c.get('name') != name:
                continue
            app = ((c.get('app') or {}).get('slug') or '')
            run = suites.get((c.get('check_suite') or {}).get('id'))
            if app == 'github-actions' and run is not None and _wf_path(run) == wf:
                mine.append(c)
            else:
                impostors.append('%s (app %r, workflow %r)' % (name, app or None, _wf_path(run) or None))
        if impostors:
            probs.append(('impostor_check', 'a check named %r came from a source other than %s: %s. A check is '
                          'trusted by where it came from, never by its name' % (name, wf, '; '.join(impostors))))
        if not mine:
            probs.append(('check_missing', 'the trusted check %r from %s has not reported on the head commit' % (name, wf)))
            continue
        last = max(mine, key=lambda c: (str(c.get('started_at') or ''), c.get('id') or 0))
        if last.get('status') != 'completed':
            probs.append(('check_inconclusive', '%r is %s, not completed' % (name, last.get('status'))))
        elif last.get('conclusion') != 'success':
            rule = 'check_failed' if last.get('conclusion') in ('failure', 'timed_out', 'action_required') else 'check_inconclusive'
            probs.append((rule, '%r concluded %r: only success counts (skipped, neutral and cancelled are not green)'
                          % (name, last.get('conclusion'))))
        if any(p in changed for p in (t.get('defined_by') or [wf])):
            self_defined.append(name)
    return probs, self_defined


def _latest_by_user(items, when):
    out = {}
    for it in sorted(items, key=lambda x: str(x.get(when) or '')):
        login = ((it.get('user') or {}).get('login') or '').lower()
        if login:
            out[login] = it
    return out


def authorize_personal(pcfg, pr, comments):
    owner = str(pcfg.get('owner_login') or '')
    if not owner or PLACEHOLDER.search(owner):
        return False, ('authorizer_unconfigured', 'the personal profile names no real owner_login (%r): a placeholder '
                       'authorizes nothing' % owner)
    head = pr['head_sha']
    for c in comments:
        if ((c.get('user') or {}).get('login') or '').lower() != owner.lower():
            continue
        if c.get('updated_at') and c.get('created_at') and c['updated_at'] != c['created_at']:
            continue
        m = AUTHORIZE.match(str(c.get('body') or '').strip().splitlines()[0] if str(c.get('body') or '').strip() else '')
        if m and m.group(1) == head:
            return True, None
    return False, ('awaiting_authorizer', 'a protected change needs the owner (%s) to comment `/kit-authorize %s` '
                   'on this head commit' % (owner, head))


def authorize_employer(ecfg, pr, reviews, commits, members):
    head, author = pr['head_sha'], pr['author'].lower()
    need = ecfg.get('required_approvals')
    if not isinstance(need, int) or isinstance(need, bool) or need < 1:
        return False, ('policy_misconfigured', 'required_approvals must be a whole number of at least 1; got %r' % need)
    allowed = {x.lower() for x in (ecfg.get('reviewer_logins') or []) if x and not PLACEHOLDER.search(x)}
    for team in (ecfg.get('reviewer_teams') or []):
        if team in (members or {}):
            allowed |= {x.lower() for x in members[team]}
    if not allowed:
        return False, ('reviewers_unknown', 'the assigned reviewers could not be read (team membership needs '
                       'the optional org-read secret in governance-gate.yml, or name reviewer_logins): nobody can approve, so it holds')
    pushers = set()
    for c in commits:
        for k in ('author', 'committer'):
            login = ((c.get(k) or {}).get('login') or '').lower()
            if login and login != 'web-flow':
                pushers.add(login)
    states = {'approved', 'changes_requested', 'dismissed'}   # GitHub review states, compared lower-case
    latest = _latest_by_user([r for r in reviews if str(r.get('state')).lower() in states], 'submitted_at')
    blocked = sorted(u for u, r in latest.items() if str(r.get('state')).lower() == 'changes_requested')
    if blocked:
        return False, ('changes_requested', 'changes requested by %s' % ', '.join(blocked))
    ok = sorted(u for u, r in latest.items() if str(r.get('state')).lower() == 'approved' and r.get('commit_id') == head
                and u in allowed and u != author and u not in pushers)
    if len(ok) >= need:
        return True, None
    return False, ('awaiting_authorizer', 'a protected change needs %d approval(s) on head %s from the assigned '
                   'reviewers, never the author or a committer; has %d' % (need, head[:12], len(ok)))


def delegated(pr, commits, changed):
    if pr['author'] != DEPENDABOT or not commits:
        return False
    for c in commits:
        if ((c.get('author') or {}).get('login') != DEPENDABOT
                or not (((c.get('commit') or {}).get('verification') or {}).get('verified'))):
            return False
    return not any(any(_match(p, m) for m in MACHINERY if m != '.github/') for p in changed)


def evaluate(cfg, pr, changed, check_runs=(), workflow_runs=(), reviews=(), comments=(), commits=(),
             members=None, base_side=()):
    """-> the decision record. Pure: every input is data the caller read from the base or the API."""
    rec = {'decision': 'hold', 'profile': cfg.get('profile'), 'pr': pr.get('number'), 'head_sha': pr.get('head_sha'),
           'rules': [], 'protected': {}, 'self_defined_checks': []}

    def hold(rule, why):
        rec['rules'].append({'rule': rule, 'reason': why})
    profile = cfg.get('profile')
    if profile not in PROFILES or not isinstance((cfg.get('profiles') or {}).get(profile), dict):
        hold('profile_unreadable', 'the base profile %r is not one of %s: nothing merges on its own' % (profile, PROFILES))
        return rec
    if not re.match(r'^[0-9a-f]{40}$', str(pr.get('head_sha') or '')) or not pr.get('author'):
        hold('pr_unreadable', 'the pull request head or author could not be read')
        return rec
    if changed is None or not list(changed):
        hold('diff_unreadable', 'the changed paths could not be read (or there are none): nothing to classify is not routine')
        return rec
    changed = list(changed)
    if delegated(pr, commits, changed):
        rec['decision'] = 'delegated'
        hold_free = 'Dependabot pull request touching no governance machinery: the Dependabot triage decides it'
        rec['rules'].append({'rule': 'delegated_to_dependabot_triage', 'reason': hold_free})
        return rec
    if pr.get('draft'):
        hold('draft', 'a draft pull request never merges on its own')
    protected = classify(changed, cfg)
    rec['protected'] = {p: c for p, (c, _w) in sorted(protected.items())}
    probs, rec['self_defined_checks'] = evaluate_checks(cfg, list(check_runs), list(workflow_runs), changed)
    for rule, why in probs:
        hold(rule, why)
    for rule, why in base_side:
        hold(rule, why)
    if protected:
        pcfg = cfg['profiles'][profile]
        if profile == 'personal':
            ok, why = authorize_personal(pcfg, pr, list(comments))
        else:
            ok, why = authorize_employer(pcfg, pr, list(reviews), list(commits), members)
        if not ok:
            hold(why[0], '%s. Protected: %s' % (why[1], ', '.join('%s (%s)' % (p, c) for p, c in sorted(rec['protected'].items())[:8])))
    if not rec['rules']:
        rec['decision'] = 'authorized' if protected else 'merge_eligible'
    return rec


# ---- the base-side checks: the BASE's checkers over the head's files, read as data ----

def git(repo, *args):
    r = subprocess.run(['git', '-C', repo] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode, r.stdout.decode('utf-8', 'replace')


def show(repo, ref, rel):
    rc, out = git(repo, 'show', '%s:%s' % (ref, rel))
    return out if rc == 0 else None


def base_side_checks(repo, merge_base, head, changed, today):
    """-> [(rule, reason)]: the floor compared with its base, and the change record, by the BASE's code."""
    sys.path.insert(0, HERE)
    import capability_floor as cf
    import protected_paths as pp
    import yaml
    out = []
    if 'capability-floor.json' in changed or 'scanner-registry.yaml' in changed:
        try:
            hdoc = json.loads(show(repo, head, 'capability-floor.json') or '')
            bdoc = json.loads(show(repo, merge_base, 'capability-floor.json') or '{}')
            hreg = yaml.safe_load(show(repo, head, 'scanner-registry.yaml') or '') or {}
            breg = yaml.safe_load(show(repo, merge_base, 'scanner-registry.yaml') or '') or {}
        except ValueError as e:
            return [('floor_unreadable', 'the floor or registry could not be read as data: %s' % e)]
        p, _state = cf.check_base(hdoc.get('floor') or [], hdoc.get('tombstones') or [], bdoc.get('floor') or [],
                                  today, bdoc.get('tombstones') or [], cf.policy_of(hdoc), ROOT)
        p += cf.policy_loosened(hdoc, bdoc) if bdoc else []
        p += cf.check_registry_base(hreg, breg, hdoc.get('selection_tombstones') or [],
                                    bdoc.get('selection_tombstones') or [], today) if breg else []
        out += [('floor_breached', x) for x in p]
    rc, diff = git(repo, 'diff', '-U0', '--no-renames', merge_base, head, '--', CHANGE_LOG)
    if rc != 0:
        return out + [('change_record_unreadable', 'the change log diff could not be read')]
    added = [ln[1:] for ln in diff.splitlines() if ln.startswith('+') and not ln.startswith('+++')]
    removed = [ln[1:] for ln in diff.splitlines() if ln.startswith('-') and not ln.startswith('---')]
    out += [('change_record', x) for x in pp.check_change(changed, added, removed)]
    return out


def load_json(path, default=None):
    """A JSON document, or newline-delimited JSON (gh api --paginate --jq '.[]'). Absent -> default."""
    if not path or not os.path.isfile(path):
        return default
    text = io.open(path, encoding='utf-8').read().strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except ValueError:
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def run(a):
    rc, mb = git(a.repo, 'merge-base', a.base, a.head)
    if rc != 0:
        print('UNKNOWN: no merge base between %s and %s: the change was NOT evaluated' % (a.base, a.head))
        return None
    mb = mb.strip()
    try:
        cfg = json.loads(show(a.repo, a.base, CONFIG) or '')
    except ValueError:
        cfg = {}
    rc, names = git(a.repo, 'diff', '--name-only', '--no-renames', mb, a.head)
    changed = [x for x in names.splitlines() if x] if rc == 0 else None
    d = a.data_dir
    pr = load_json(os.path.join(d, 'pr.json'), {}) or {}
    prr = {'number': pr.get('number'), 'head_sha': (pr.get('head') or {}).get('sha'),
           'author': (pr.get('user') or {}).get('login'), 'draft': bool(pr.get('draft'))}
    if prr['head_sha'] != a.head:
        print('UNKNOWN: the fetched head %s is not the pull request head %s' % (a.head, prr['head_sha']))
        return None
    runs = load_json(os.path.join(d, 'workflow-runs.json'), [])
    if isinstance(runs, dict):
        runs = runs.get('workflow_runs') or []
    base_side = base_side_checks(a.repo, mb, a.head, changed or [], a.today) if changed else []
    return evaluate(cfg, prr, changed, load_json(os.path.join(d, 'check-runs.json'), []), runs,
                    load_json(os.path.join(d, 'reviews.json'), []), load_json(os.path.join(d, 'comments.json'), []),
                    load_json(os.path.join(d, 'commits.json'), []), load_json(os.path.join(d, 'members.json'), None),
                    base_side)


def self_test():
    head = 'a' * 40
    cfg = json.loads(io.open(os.path.join(ROOT, CONFIG), encoding='utf-8').read())
    cfg = dict(cfg, profiles=dict(cfg['profiles'], personal={'owner_login': 'owner'}))
    pr = {'number': 1, 'head_sha': head, 'author': 'owner'}
    green = [{'id': 1, 'name': 'Self-test required', 'status': 'completed', 'conclusion': 'success',
              'app': {'slug': 'github-actions'}, 'check_suite': {'id': 9}}]
    runs = [{'check_suite_id': 9, 'path': '.github/workflows/self-test.yml'}]
    fails = []

    def expect(label, got, want):
        if got['decision'] != want:
            fails.append('%s: %s %s' % (label, got['decision'], got['rules']))
    expect('routine green', evaluate(cfg, pr, ['docs/a.md'], green, runs), 'merge_eligible')
    expect('routine red', evaluate(cfg, pr, ['docs/a.md'], [dict(green[0], conclusion='failure')], runs), 'hold')
    expect('protected unauthorized', evaluate(cfg, pr, ['scripts/governance_gate.py'], green, runs), 'hold')
    ok = [{'user': {'login': 'owner'}, 'body': '/kit-authorize ' + head}]
    expect('protected authorized', evaluate(cfg, pr, ['scripts/governance_gate.py'], green, runs, comments=ok), 'authorized')
    expect('unknown profile', evaluate(dict(cfg, profile='team'), pr, ['docs/a.md'], green, runs), 'hold')
    if fails:
        print('SELF-TEST FAILED: ' + '; '.join(fails))
        return 1
    print('self-test ok: 5 cases (routine green/red, protected held/authorized, unknown profile)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--repo', default=ROOT, help='the TRUSTED base checkout, holding the PR head as objects')
    ap.add_argument('--base', help='the base branch commit (the trusted checkout)')
    ap.add_argument('--head', help='the pull request head commit, fetched as objects only')
    ap.add_argument('--data-dir', help='pr.json, check-runs.json, workflow-runs.json, reviews.json, comments.json, '
                    'commits.json, members.json (optional), read from the API as data')
    ap.add_argument('--today', default=datetime.date.today().isoformat())
    ap.add_argument('--out', help='write the decision record (JSON) here')
    ap.add_argument('--github-output', help='the step output file ($GITHUB_OUTPUT); decision=<value> is appended')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.base and a.head and a.data_dir):
        ap.print_help()
        return 2
    rec = run(a)
    if rec is None:
        if a.github_output:
            with io.open(a.github_output, 'a', encoding='utf-8') as fh:
                fh.write('decision=hold\n')
        return 2
    if a.out:
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(rec, indent=2, sort_keys=True))
    print('governance gate: %s (profile %s)' % (rec['decision'].upper(), rec['profile']))
    for p, c in sorted(rec['protected'].items()):
        print('  protected  %-55s %s' % (p, c))
    for r in rec['rules']:
        print('  %-28s %s' % (r['rule'], r['reason']))
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('decision=%s\n' % (rec['decision'] if rec['decision'] in DECISIONS else 'hold'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
