#!/usr/bin/env python3
"""Every Dependabot-triage job's `permissions:` covers every GitHub call its steps make. STATIC.

FOUND HOSTED (Release 4 on main, PR #5, 2026-11-06)
    "Label, request review, comment" failed: `GraphQL: Resource not accessible by integration
    (repository.pullRequest.commits.nodes.0)` -- then "a label or the comment could not be written;
    the PR still needs a human", exit 1. The human-review job held `pull-requests: write` and
    `issues: write` and NO `contents`: `gh pr edit` / `gh pr view` / `gh pr close` look the pull
    request up through GraphQL, and that lookup reads its commits, which needs `contents: read`.
    A job-level `permissions:` block sets every scope it does not name to none.

THE MAP (the least each call needs; a job must grant at least the strongest of its calls)
    gh pr view | edit | close | comment | checks | diff   contents: read, pull-requests: read
                (edit / close / comment / --add-label / --add-reviewer also pull-requests: write)
    gh pr merge (and --auto)                                 contents: write, pull-requests: write
    gh pr merge --disable-auto                               contents: read, pull-requests: write
    gh label create, gh api .../labels                      issues: write / issues: read
    gh api .../issues/<n>/comments (GET) / -X PATCH|POST     issues: read / issues: write
    gh api .../pulls/<n>/files                               pull-requests: read
    gh api .../branches | rules                              contents: read
    actions/checkout                                         contents: read

WHAT IT PROVES
    T1  every job of reusable-dependabot-triage.yml grants what its calls need (each job named).
    T2  the caller grants the union (check_caller_permissions.py holds that too; repeated here so
        the triage file is held on its own).
    T3  mutants: human-review without contents, auto-merge with contents: read, and close without
        contents each fail T1.

EXIT  0 proven   1 a job grants less than a call needs (named)   2 could not be checked
"""
import copy
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-dependabot-triage.yml')
CALLERS = [os.path.join(ROOT, '.github', 'workflows', 'dependabot-triage.yml'),
           os.path.join(ROOT, 'templates', 'dependabot-triage.yml')]
LEVEL = {'none': 0, 'read': 1, 'write': 2}
FAILS = []

# (regex over one step's run text or uses, {scope: level}, label)
RULES = [
    (r'\bgh\s+pr\s+merge\s+--disable-auto\b', {'contents': 'read', 'pull-requests': 'write'},
     'gh pr merge --disable-auto'),
    (r'\bgh\s+pr\s+merge\b(?!\s+--disable-auto)', {'contents': 'write', 'pull-requests': 'write'}, 'gh pr merge'),
    (r'\bgh\s+pr\s+(edit|close|comment|review|ready|reopen)\b', {'contents': 'read', 'pull-requests': 'write'},
     'gh pr edit/close/comment (GraphQL reads the commits)'),
    (r'\bgh\s+pr\s+(view|checks|diff|list|status)\b', {'contents': 'read', 'pull-requests': 'read'},
     'gh pr view (GraphQL reads the commits)'),
    (r'\bgh\s+label\s+create\b', {'issues': 'write'}, 'gh label create'),
    (r'\bgh\s+api\b[^\n]*repos/[^\n]*/labels', {'issues': 'read'}, 'gh api labels'),
    (r'\bgh\s+api\s+-X\s+(PATCH|POST|PUT|DELETE)\b[^\n]*issues/', {'issues': 'write'}, 'gh api write issues/comments'),
    (r'\bgh\s+api\b(?![^\n]*-X\s+(PATCH|POST|PUT|DELETE))[^\n]*issues/[^\n]*comments', {'issues': 'read'},
     'gh api read issue comments'),
    (r'\bgh\s+api\b[^\n]*pulls/[^\n]*/files', {'pull-requests': 'read'}, 'gh api pull files'),
    (r'\bgh\s+api\b[^\n]*(branches|rules)/', {'contents': 'read'}, 'gh api branches/rules'),
    (r'actions/checkout@', {'contents': 'read'}, 'actions/checkout'),
]


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)


def commands(run):
    """The command text of a shell body: comments dropped and quoted strings blanked, so a message or
    an embedded program that MENTIONS `gh pr merge` is not read as calling it."""
    out, heredoc = [], None
    for line in (run or '').splitlines():
        t = line.strip()
        if heredoc:
            if t == heredoc:
                heredoc = None
            continue                         # an embedded program's text is not a shell call
        m = re.search(r"<<-?\s*['\"]?([A-Za-z_]+)['\"]?", t)
        if m:
            heredoc = m.group(1)
        if t.startswith('#') or re.match(r'(echo|printf|note|s\.append)\b', t):
            continue                         # a comment or a message mentions; it does not call
        out.append(t)
    return '\n'.join(out)


def needs_of(job):
    need, why = {}, {}
    for st in job.get('steps') or []:
        text = commands(st.get('run')) + '\n' + (st.get('uses') or '')
        for rx, scopes, label in RULES:
            if re.search(rx, text):
                for s, lv in scopes.items():
                    if LEVEL[lv] > LEVEL[need.get(s, 'none')]:
                        need[s], why[s] = lv, label
    return need, why


def problems(doc, top=None):
    out = []
    for jn, job in (doc.get('jobs') or {}).items():
        perms = job.get('permissions', top if top is not None else doc.get('permissions'))
        perms = perms if isinstance(perms, dict) else {}
        need, why = needs_of(job)
        for s, lv in sorted(need.items()):
            got = perms.get(s, 'none')
            if LEVEL.get(got, 0) < LEVEL[lv]:
                out.append('job %s: %s needs %s: %s, granted %s' % (jn, why[s], s, lv, got))
    return out


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not os.path.isfile(WF):
        print('UNKNOWN: %s is missing.' % WF)
        return 2
    doc = yaml.safe_load(io.open(WF, encoding='utf-8').read())
    probs = problems(doc)
    for p in probs:
        check(False, 'T1 ' + p)
    for jn, job in (doc.get('jobs') or {}).items():
        need, _ = needs_of(job)
        if not [p for p in probs if p.startswith('job %s:' % jn)]:
            check(True, 'T1 job %s grants what its calls need %s' % (jn, dict(sorted(need.items()))))
    union = {}
    for job in (doc.get('jobs') or {}).values():
        for s, lv in ((job.get('permissions') or {}) if isinstance(job.get('permissions'), dict) else {}).items():
            if LEVEL.get(lv, 0) > LEVEL.get(union.get(s, 'none'), 0):
                union[s] = lv
    for c in CALLERS:
        if not os.path.isfile(c):
            continue
        cd = yaml.safe_load(io.open(c, encoding='utf-8').read())
        for jn, job in (cd.get('jobs') or {}).items():
            if 'reusable-dependabot-triage.yml' in str(job.get('uses') or ''):
                g = job.get('permissions') or {}
                short = [s for s, lv in union.items() if LEVEL.get(g.get(s, 'none'), 0) < LEVEL[lv]]
                check(not short, 'T2 %s job %s grants the triage union %s (short: %s)'
                      % (os.path.relpath(c, ROOT), jn, union, short))
    for jn, mut, label in (('human-review', lambda p: p.pop('contents', None), 'human-review without contents'),
                           ('auto-merge', lambda p: p.__setitem__('contents', 'read'), 'auto-merge with contents: read'),
                           ('close', lambda p: p.pop('contents', None), 'close without contents')):
        if jn not in (doc.get('jobs') or {}):
            continue
        m = copy.deepcopy(doc)
        mut(m['jobs'][jn].setdefault('permissions', {}))
        check(bool([p for p in problems(m) if p.startswith('job %s:' % jn)]), 'T3 mutant caught: %s' % label)
    print()
    if FAILS:
        print('FAIL: %d check(s): a triage job grants less than a call it makes needs.' % len(FAILS))
        return 1
    print('PASS: every Dependabot-triage job grants what each of its GitHub calls needs, and the callers grant the union.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
